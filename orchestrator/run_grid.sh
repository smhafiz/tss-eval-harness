#!/usr/bin/env bash
#
# Builds both adapter binaries and sweeps the (n,t) grid, writing one
# schema-conformant JSON result per cell into results/<impl>/.
#
# Usage:
#   orchestrator/run_grid.sh [options]
#
#   --grid=PATH             grid file to sweep (default orchestrator/grid.tsv;
#                           use orchestrator/smoke-grid.tsv for a fast check)
#   --levels="112 128"      tr-ecdsa CL security levels to sweep per row
#   --include-slow-levels   shorthand for --levels="112 128 192 256"
#   --sign-trials=N         repeated signings per cell (default 8)
#   --pre-params-timeout=D  tss-lib per-party safe-prime budget (default 5m)
#   --skip-build            reuse already-built binaries
#   --only=IMPL             run just one of: tr-ecdsa, tss-lib
#
# A failing cell logs to stderr and increments a failure counter rather than
# aborting the sweep — one bad (n,t) must not cost the rest of the grid. The
# exit status is the number of failed cells (capped at 125).
#
# Regenerate the aggregate afterwards with:  python3 aggregator/aggregate.py

set -uo pipefail

HARNESS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HARNESS_ROOT"

# shellcheck source=../repos.env
source "$HARNESS_ROOT/repos.env"

GRID="$HARNESS_ROOT/orchestrator/grid.tsv"
LEVELS="112 128"
SIGN_TRIALS=8
PRE_PARAMS_TIMEOUT=5m
SKIP_BUILD=0
ONLY=""

for arg in "$@"; do
  case "$arg" in
    --grid=*)               GRID="${arg#*=}" ;;
    --levels=*)             LEVELS="${arg#*=}" ;;
    --include-slow-levels)  LEVELS="112 128 192 256" ;;
    --sign-trials=*)        SIGN_TRIALS="${arg#*=}" ;;
    --pre-params-timeout=*) PRE_PARAMS_TIMEOUT="${arg#*=}" ;;
    --skip-build)           SKIP_BUILD=1 ;;
    --only=*)               ONLY="${arg#*=}" ;;
    -h|--help)              sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 64 ;;
  esac
done

[[ -f "$GRID" ]] || { echo "grid file not found: $GRID" >&2; exit 66; }

run_trecdsa=1; run_tsslib=1
case "$ONLY" in
  "")        ;;
  tr-ecdsa)  run_tsslib=0 ;;
  tss-lib)   run_trecdsa=0 ;;
  *) echo "--only must be tr-ecdsa or tss-lib" >&2; exit 64 ;;
esac

mkdir -p "$HARNESS_ROOT/results/tr-ecdsa" "$HARNESS_ROOT/results/tss-lib"

# Short SHA of the *implementation* repo under test — provenance is "what code
# was actually benchmarked", not what revision of this harness drove it. Both
# targets are moving under active development.
impl_commit() {
  git -C "$1" rev-parse --short HEAD 2>/dev/null || echo unknown
}

# ---------------------------------------------------------------- build ----

# Overridable so a prebuilt binary elsewhere can be driven with --skip-build.
TRECDSA_EVAL="${TRECDSA_EVAL:-$TECDSA_BUILD_DIR/trecdsa/trecdsa-eval}"
TSSLIB_EVAL="${TSSLIB_EVAL:-$TECDSA_BUILD_DIR/tsslib/tecdsa-eval}"

build_trecdsa() {
  # The eval app lives inside the TR-ECDSA repo (apps/eval) — it already had an
  # eval/bench scaffold to extend, and it writes the schema JSON natively, so
  # there is no adapter shim on the harness side. Bench and tests are off:
  # this build exists only to produce trecdsa-eval.
  local build_dir="$TECDSA_BUILD_DIR/trecdsa"
  echo "==> building trecdsa-eval into $build_dir"
  cmake -S "$TRECDSA_REPO" -B "$build_dir" \
        -DCMAKE_BUILD_TYPE=Release \
        -DTRECDSA_BUILD_EVAL=ON \
        -DTRECDSA_BUILD_BENCH=OFF \
        -DTRECDSA_BUILD_TESTS=OFF >/dev/null || return 1
  cmake --build "$build_dir" --target trecdsa-eval -j "$(getconf _NPROCESSORS_ONLN)" >/dev/null || return 1
  [[ -x "$TRECDSA_EVAL" ]] || TRECDSA_EVAL="$(find "$build_dir" -name trecdsa-eval -type f -perm -u+x | head -1)"
  [[ -x "$TRECDSA_EVAL" ]]
}

build_tsslib() {
  # Standalone Go module; go.mod `replace`s bnb-chain/tss-lib to $TSSLIB_REPO,
  # so this benchmarks the local checkout, not the proxy's copy.
  echo "==> building tecdsa-eval into $TECDSA_BUILD_DIR/tsslib"
  mkdir -p "$TECDSA_BUILD_DIR/tsslib"
  ( cd "$HARNESS_ROOT/adapters/tss-lib" && go build -o "$TSSLIB_EVAL" ./cmd/tecdsa-eval )
}

if [[ "$SKIP_BUILD" -eq 1 ]]; then
  # Nothing to build — but fail loudly now rather than once per cell.
  [[ "$run_trecdsa" -eq 1 && ! -x "$TRECDSA_EVAL" ]] && {
    echo "!! --skip-build but no executable at $TRECDSA_EVAL — skipping tr-ecdsa cells" >&2; run_trecdsa=0; }
  [[ "$run_tsslib" -eq 1 && ! -x "$TSSLIB_EVAL" ]] && {
    echo "!! --skip-build but no executable at $TSSLIB_EVAL — skipping tss-lib cells" >&2; run_tsslib=0; }
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  mkdir -p "$TECDSA_BUILD_DIR"
  if [[ "$run_trecdsa" -eq 1 ]] && ! build_trecdsa; then
    echo "!! trecdsa-eval build failed — skipping tr-ecdsa cells" >&2
    run_trecdsa=0
  fi
  if [[ "$run_tsslib" -eq 1 ]] && ! build_tsslib; then
    echo "!! tecdsa-eval build failed — skipping tss-lib cells" >&2
    run_tsslib=0
  fi
fi

TRECDSA_COMMIT="$(impl_commit "$TRECDSA_REPO")"
TSSLIB_COMMIT="$(impl_commit "$TSSLIB_REPO")"

# ------------------------------------------------------------- the sweep ----

failures=0
cells=0

run_cell() {  # run_cell <description> <output path> <command...>
  local desc="$1" out="$2"; shift 2
  cells=$((cells + 1))
  echo "--> $desc"
  if "$@"; then
    echo "    wrote $(basename "$out")"
  else
    echo "!! FAILED: $desc" >&2
    failures=$((failures + 1))
    rm -f "$out"   # never leave a truncated file for the aggregator to read
  fi
}

while IFS=$'\t' read -r n t tsslib_mode; do
  [[ -z "${n:-}" || "$n" == \#* ]] && continue

  if [[ "$run_trecdsa" -eq 1 ]]; then
    for level in $LEVELS; do
      out="$HARNESS_ROOT/results/tr-ecdsa/tr-ecdsa_${level}_n${n}_t${t}_$(date +%s).json"
      run_cell "tr-ecdsa level=$level n=$n t=$t" "$out" \
        "$TRECDSA_EVAL" \
          --level="$level" --n="$n" --t="$t" \
          --sign-trials="$SIGN_TRIALS" \
          --out="$out" --git-commit="$TRECDSA_COMMIT"
    done
  fi

  if [[ "$run_tsslib" -eq 1 ]]; then
    # tss-lib has no security-level knob (SCHEMA.md caveat 4): one run per row,
    # labelled by its fixed curve.
    out="$HARNESS_ROOT/results/tss-lib/tss-lib_secp256k1_n${n}_t${t}_$(date +%s).json"
    run_cell "tss-lib n=$n t=$t mode=${tsslib_mode:-live}" "$out" \
      "$TSSLIB_EVAL" \
        -n="$n" -t="$t" -mode="${tsslib_mode:-live}" \
        -sign-trials="$SIGN_TRIALS" \
        -pre-params-timeout="$PRE_PARAMS_TIMEOUT" \
        -out="$out" -git-commit="$TSSLIB_COMMIT"
  fi
done < "$GRID"

echo
echo "grid complete: $((cells - failures))/$cells cells succeeded"
if [[ "$failures" -gt 0 ]]; then
  echo "$failures cell(s) failed — see stderr above; the rest of the grid is intact" >&2
fi
echo "next: python3 aggregator/aggregate.py"

exit $(( failures > 125 ? 125 : failures ))
