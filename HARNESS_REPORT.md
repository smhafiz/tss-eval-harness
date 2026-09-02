# TSS Eval Harness — how it works and what it has evaluated so far

> **Provenance note (2026-09-01):** parts of this repository were lost to
> filesystem/OneDrive damage and have been **reconstructed from this document**.
> See [Reconstruction status](#reconstruction-status) at the bottom before
> trusting any file here to be the original. Result *data* was not
> reconstructed.

## Purpose

This repository is a **cross-implementation benchmark harness for threshold-ECDSA
(TSS) protocols**. Different implementations of threshold ECDSA use different
round structures, different homomorphic-encryption backends, and different
tuning knobs, which makes it easy to produce numbers that look comparable but
aren't. The harness's job is to run each implementation through the same
*scenario* (party count `n`, threshold `t`, repeated signing trials), capture
timing/bandwidth/object-size/correctness data in one shared JSON schema, and
be explicit — in the schema itself — about exactly where a side-by-side
comparison stops being valid.

The harness itself is intentionally thin: it does not implement any
cryptography. It builds and drives each target implementation's own code
through a small per-implementation **adapter**, and treats the implementation
repos as external dependencies checked out elsewhere on disk.

## How it's structured

```
repos.env            # paths to the external implementation repos + build-dir override
adapters/tss-lib/    # Go adapter: builds a tecdsa-eval binary against bnb-chain/tss-lib
orchestrator/        # grid.tsv (the (n,t) sweep) + run_grid.sh (build-and-run driver)
schema/              # result_schema.json + SCHEMA.md (field reference and caveats)
results/<impl>/*.json# one JSON file per (implementation, security-level, n, t) run
aggregator/          # aggregate.py: results/*.json -> results/summary.csv + summary.md
```

**`repos.env`** points at the two implementation repos under test
(`TRECDSA_REPO`, `TSSLIB_REPO`) and redirects compiled build artifacts to
`~/.tss-eval-build` outside the OneDrive-synced tree — a stale CMake `build/`
directory previously went cloud-only and became unreadable (`ETIMEDOUT`)
after OneDrive evicted it locally, so only source/schema/scripts/JSON stay
synced; build output does not.

**Adapters** are the only implementation-specific code. Each one links
against the target library, runs keygen + repeated signing, times the phases,
counts wire bytes, samples object sizes, checks signature validity, and
serializes a schema-conformant JSON file. tr-ecdsa's adapter (`trecdsa-eval`)
actually lives *inside* the TR-ECDSA repo itself (`apps/eval`, built via a
`-DTRECDSA_BUILD_EVAL=ON` CMake flag) since that repo already has an
eval/bench app scaffold to extend; tss-lib had no such thing, so
[adapters/tss-lib](adapters/tss-lib) is a standalone Go module + `cmd/tecdsa-eval`
binary written for this harness.

**`orchestrator/run_grid.sh`** sources `repos.env`, builds both binaries,
then reads `orchestrator/grid.tsv` (`n`, `t`, tss-lib keygen mode) and, for
each row, runs tr-ecdsa once per security level (`112 128` by default, or
`112 128 192 256` with `--include-slow-levels`) and tss-lib once, writing
each result to `results/<impl>/<impl>_..._<unixts>.json`. `112` is kept even
though it's tr-ecdsa's weakest tier in isolation, because it's the one level
where tr-ecdsa and tss-lib are actually apples-to-apples (see "effective
security bits" below). A failing cell logs to stderr and increments a
failure counter rather than aborting the sweep, so one bad `(n,t)`
combination doesn't lose the rest of the grid. `orchestrator/smoke-grid.tsv`
is a 2-row subset for fast end-to-end sanity checks before committing to a
full run.

**`schema/result_schema.json` + `SCHEMA.md`** define one shared JSON shape
both adapters must emit, using protocol-agnostic field names (`enc_*` rather
than `paillier_*`/`cl_*`) so the schema itself doesn't presume one
implementation's design. `SCHEMA.md` documents non-comparability caveats
(round-boundary mismatch, differing meaning of "key share," `null` vs `0`
for skipped measurements, etc.) — this is the harness's main defense against
someone reading the aggregated table and drawing an apples-to-apples
conclusion that isn't warranted.

**Effective security bits.** `security.label` isn't always an honest
strength number by itself: tr-ecdsa scales its EC curve and its CL-HSM group
together from one requested level, so its label already is the real
strength — but tss-lib is hardwired to secp256k1 (a 256-bit curve, NIST
128-bit tier) paired with a static Paillier-2048 modulus (NIST 112-bit
tier), a mismatched pair whose real-world strength is capped by the weaker
component. `aggregator/aggregate.py` now derives `curve_security_bits`,
`enc_security_bits`, and `overall_security_bits = min(curve, enc)` per row
using NIST SP 800-57's equivalence tiers, and adds a dedicated "Security
strength" table to `results/summary.md`. This is why tss-lib's row lands at
112 effective bits even though the schema's `security.label` field just says
`"secp256k1"` — and why 112 stays in the default sweep for tr-ecdsa: it's
the only level tr-ecdsa and tss-lib genuinely share once tss-lib's weaker
Paillier component is accounted for, so dropping it would remove the one
real same-strength comparison point in the grid.

**`aggregator/aggregate.py`** (stdlib-only Python) reads every
`results/<impl>/*.json`, and writes `results/summary.csv` (flat, one row per
run) and `results/summary.md` (grouped by `(n, t)`, with timing/bandwidth/
object-size/correctness tables, and the caveats section from `SCHEMA.md`
appended verbatim so the summary can't be read out of context of its own
limitations).

## Workflow end to end

1. Check out both implementation repos; point `repos.env` at them.
2. `orchestrator/run_grid.sh [--grid=...] [--levels=...] [--sign-trials=N] [--include-slow-levels]`
   builds both adapter binaries and sweeps `grid.tsv`, writing one JSON file
   per cell into `results/<impl>/`.
3. `aggregator/aggregate.py` turns the accumulated JSON files into
   `results/summary.csv` / `results/summary.md`.

Every result file records the *implementation repo's* git commit
(`git_commit`), not the harness's own — provenance is "what code was
actually benchmarked," which matters because both target repos are moving
targets under active development.

---

## Projects evaluated so far

Two implementations have been run through the harness to date, across the
grid `(n,t) ∈ {(3,1), (3,2), (5,2), (5,4), (10,5)}` at security levels
112/128 (tr-ecdsa) and secp256k1/Paillier-2048 (tss-lib, no independent
level knob) — 15 result files total (10 tr-ecdsa, 5 tss-lib).

### 1. TR-ECDSA (`Three-Round-Multiparty-ECDSA`)

A C++17 implementation of a 3-round threshold-ECDSA protocol using CL-HSM
(class-group) homomorphic encryption instead of Paillier, sweepable across
four CL security levels (112/128/192/256-bit).

- **Build/execute**: CMake, built with a dedicated `-DTRECDSA_BUILD_EVAL=ON`
  flag (bench/tests disabled) producing a `trecdsa-eval` binary that takes
  `--level/--n/--t/--sign-trials/--out/--git-commit` and writes the schema
  JSON directly — no adapter shim was needed on the harness side since the
  eval app was written to speak the schema natively.
- **Challenge — proof size isn't directly measurable**: the round-1 ZKAoK
  proof's internal fields aren't exposed by the library, so its serialized
  size can't be measured directly.
  **Solution**: estimate it from a known size bound and tag that one number
  `"exactness": "upper_bound_estimate"` in `bandwidth_bytes.per_round`, while
  rounds 2–3 (which *are* measured exactly) are tagged `"exact"` — so
  consumers of the data know which numbers to trust to the byte and which
  are approximate.
- **Challenge — no shared axis with tss-lib**: tr-ecdsa exposes an
  independent CL security-level knob (112–256-bit) that tss-lib has no
  equivalent for (tss-lib is fixed to secp256k1 + Paillier-2048).
  **Solution**: documented as non-comparability caveat #4 rather than forcing
  a fake mapping; tr-ecdsa's levels are swept independently and tss-lib rows
  are simply repeated once per `(n,t)` in the merged table.
- **Result at a glance**: fast keygen and setup (well under a second even at
  n=10), but signing cost grows sharply with `t` and security level (e.g.
  112-bit n=10,t=5 signs in ~4.5s vs. ~7.7s at 128-bit) — the 3-round
  protocol trades round count for heavier CL-HSM arithmetic per round.

### 2. tss-lib (`bnb-chain/tss-lib`)

A Go implementation of GG18, a 9-round threshold-ECDSA protocol using
Paillier encryption for MtA (multiplicative-to-additive) share conversion.
No dedicated eval tooling existed in the repo, so the harness's
`adapters/tss-lib` module was written from scratch against tss-lib's public
API and its own test-harness message-dispatch pattern.

- **Build/execute**: standalone Go module (`go build ./cmd/tecdsa-eval`)
  producing a binary with `-n/-t/-mode/-sign-trials/-pre-params-timeout/-out/-git-commit`
  flags. `internal/dispatch.go`'s `RunMessageLoop` reuses tss-lib's own
  `test.SharedPartyUpdater` goroutine/channel pattern (from tss-lib's own
  `_test.go` files) to drive keygen and signing to completion in-process,
  generalized with Go generics so the same loop drives both the keygen and
  signing party types.
- **Challenge — Paillier/safe-prime pre-param generation is slow**:
  `keygen.GeneratePreParams` (generating safe primes for each party's
  Paillier keypair) can take minutes per party, dominating any live-mode run
  and making a full grid sweep expensive.
  **Solution**: exposed as a configurable `--pre-params-timeout` (default 5m
  in the orchestrator) and timed per-party into the `setup` phase so the
  cost is visible rather than hidden inside "keygen."
- **Challenge — bundled test fixtures only cover one `(n,t)`**: tss-lib
  ships precomputed keygen fixtures for exactly `(n=5, t=2)`; loading them
  skips live pre-param generation and the interactive keygen protocol
  entirely, so there's no real timing to report for those phases.
  **Solution**: a `mode=fixtures|live` switch. In fixtures mode, `setup` and
  `dkg_or_keygen` are explicitly serialized as JSON `null` (never `0`) so a
  skipped measurement can never be silently averaged in as "instant";
  `grid.tsv` marks exactly one row (`5 2 fixtures`) this way, and every other
  `(n,t)` cell runs `mode=live` for real numbers.
  **Trade-off accepted**: fixtures mode is fast but only produces real
  signing/bandwidth/object-size numbers for `(5,2)`, not keygen numbers.
- **Challenge — no native per-round boundary to hook**: tss-lib doesn't
  expose a round index on outgoing messages, only a `Type()` string like
  `"...SignRound3Message"`.
  **Solution**: `internal/signrun.go` regex-matches `SignRound(\d+)` out of
  the type string to bucket bandwidth by round. This is explicitly marked
  best-effort (`per_round_comparable_across_impl: false`) since
  pattern-matching a message type name is not the same thing as tr-ecdsa's
  three native protocol rounds — GG18 has 9 rounds, and even within tss-lib
  the bucketing doesn't necessarily line up 1:1 with a formal protocol
  round.
- **Challenge — "realistic" vs "fast" protocol config**: tss-lib's own test
  suite disables some ZK proofs (`SetNoProofMod`/`SetNoProofFac`) purely for
  test speed.
  **Solution**: the adapter deliberately never calls those setters, so
  measured numbers reflect the full, production-representative protocol,
  not a stripped-down test configuration — documented as caveat #10 so
  nobody "fixes" this later thinking it's an oversight.
- **Challenge — `enc_key_share`/`enc_public_key` mean something different
  here than in tr-ecdsa**: GG18 does not threshold-ize Paillier — each party
  generates and keeps its own independent, full Paillier keypair used only
  for local MtA computations, unlike tr-ecdsa's genuinely-shared CL secret
  key.
  **Solution**: same field names for schema uniformity (both adapters must
  conform to one shape), but caveats #2–#3 spell out the different
  cryptographic guarantee explicitly so the numbers aren't read as
  apples-to-apples key-share sizes.
- **Result at a glance**: setup (pre-params) is expensive relative to
  tr-ecdsa (seconds vs. tens of milliseconds) and keygen cost climbs
  steeply with `n` (~12.2s at n=10,t=5 vs. ~2.3s at n=3,t=1), but per-message
  signing itself is markedly faster than tr-ecdsa at every grid cell (e.g.
  ~170ms vs. tr-ecdsa's ~695–1155ms at n=3,t=1) — Paillier-based MtA is
  cheaper per signing operation than tr-ecdsa's CL-HSM approach even though
  GG18 needs 9 rounds to tr-ecdsa's 3.

---

## Reading the aggregated results

`results/summary.md` is generated, not hand-maintained — regenerate it with
`python3 aggregator/aggregate.py` after any new grid run. It always carries
the full non-comparability caveats section from `schema/SCHEMA.md` at the
bottom; that section is load-bearing and should be read before drawing any
conclusion from a side-by-side row in the timing/bandwidth/object-size
tables above it.

---

## Reconstruction status

On 2026-09-01 this tree was found damaged: several files had been renamed with
numeric suffixes (`aggregate 500 192.py`, `result_schema 230.json`, even
`.git/config 500 236`) and many were missing outright. The git repository has
**no commits**, so nothing was recoverable from history. What follows is what
was lost and what was done about it.

### Intact — original, untouched

- `schema/result_schema.json`, `aggregator/aggregate.py`,
  `orchestrator/smoke-grid.tsv`, `repos.env`,
  `adapters/tss-lib/{go.mod,go.sum}`, `adapters/tss-lib/internal/signrun.go`,
  `adapters/tss-lib/cmd/tecdsa-eval/main.go` (filenames restored where mangled)
- All five `results/tss-lib/*.json`, one of ten `results/tr-ecdsa/*.json`,
  and `results/report_cl26_gg18.{md,pdf}`

### Reconstructed from this document — verified

- **`adapters/tss-lib/internal/{stats,dispatch,keygenrun,objects,result}.go`**.
  Verified by compiling against upstream `tss-lib v3.0.0` and re-running both
  modes. The output is not merely plausible — it reproduces the surviving
  originals: `(3,1)` live mode gives `bandwidth_bytes.total` of **21,414 bytes,
  identical** to the original file, with matching `trials` (3/1/8); `(5,2)`
  fixtures mode reproduces every `object_sizes_bytes` value exactly and every
  `per_round` bucket to within 1–2 bytes. Both outputs validate against
  `result_schema.json`.
- **`orchestrator/run_grid.sh`** and **`orchestrator/grid.tsv`**. Rebuilt from
  the flags, behaviours and grid documented above. `grid.tsv` is certain
  (the five cells and the single `5 2 fixtures` row are stated here and
  corroborated by the surviving result files). `run_grid.sh` is *behaviourally*
  faithful — same flags, same output paths, same non-aborting failure
  handling — but its exact original text is gone. **Not yet executed
  end-to-end**, because it needs the TR-ECDSA repo (see below).
- **`schema/SCHEMA.md`**. The caveat *numbering* is anchored by surviving
  citations — caveat 1 (round bucketing) from `signrun.go`, caveat 8 (fixtures
  → `null`) from the `notes` field of the surviving `(5,2)` result, and
  caveats 2/3/4/10 from this document. Caveats 5–7, 9 and 11–12 are written
  from the behaviour of the surviving code and data. The field reference is
  derived from `result_schema.json` and the surviving results.

### The compiled eval binaries survive — the harness still runs

Both adapter binaries were found intact in `~/.tss-eval-build` (the
out-of-OneDrive location `repos.env` redirects build output to — that decision
is what saved them), built 2026-07-17 11:37, minutes before the result files
were written at 11:40–11:47:

- `~/.tss-eval-build/trecdsa/trecdsa-eval`
- `~/.tss-eval-build/tsslib/tecdsa-eval`

That build directory's `CMakeCache.txt` confirms this document's description of
the tr-ecdsa build exactly — `TRECDSA_BUILD_EVAL:BOOL=ON`,
`TRECDSA_BUILD_BENCH:BOOL=OFF`, `TRECDSA_BUILD_TESTS:BOOL=OFF` — and its
`compile_commands.json` shows `apps/eval/main.cpp` compiled. `trecdsa-eval`'s
usage string matches the documented flags.

Both binaries still execute. Re-running `trecdsa-eval --level=112 --n=5 --t=4
--setup-trials=2 --dkg-trials=2 --sign-trials=8` reproduces the one surviving
tr-ecdsa result: identical `object_sizes_bytes`, identical round-1 and round-2
bandwidth, `total` within 8 bytes, and the same distinctive JSON layout —
confirming the stored results were written by this binary. The original
`tecdsa-eval` likewise still runs, and its `(5,2)` fixtures output
(59,693 bandwidth bytes) sits between the stored original (59,694) and the
reconstruction above (59,692), which independently confirms the reconstructed
Go code against the *original compiled binary*, not merely against stored JSON.

**Consequence: the full grid can be re-run today**, without restoring either
repo, by pointing `run_grid.sh` at these binaries with `--skip-build`. What is
lost is the ability to *rebuild* them from source.

Note that TR-ECDSA's in-repo `build/` directory is misleading here: it dates
from 2026-06-26, three weeks pre-eval, and records `BENCH=ON`/`TESTS=ON` with
no `TRECDSA_BUILD_EVAL` entry at all. It is exactly the stale-OneDrive-build
artifact `repos.env` warns about, and says nothing about the eval-era build.

### Not recovered (source only)

- **`apps/eval/main.cpp`** and the `TRECDSA_BUILD_EVAL` CMake option were lost
  (written as uncommitted working-tree changes on 2026-07-17, two weeks after
  the last commit, and absent from the Jul 2 source zip). **Both have since
  been rewritten** — see "The eval app, rewritten" below.
- **The rest of the TR-ECDSA repo** is restorable from that zip, which holds
  `CMakeLists.txt`, `src/protocol/*`, `include/trecdsa/*`, `apps/{bench,cli}`,
  `tests/*` and the bundled BICYCL — everything the damaged checkout lost
  except `apps/eval`.
- **The tss-lib checkout** is missing 34 files against upstream v3.0.0,
  including the entire `tss/` core package (`curve`, `error`, `message`,
  `party`, `peers`, `wire`) and `crypto/{commitments,dlnproof}`, which is why
  it does not build. It is stock upstream and restorable by re-cloning. Its
  `test/_ecdsa_fixtures/keygen_data_{0..4}.json` survive, so fixtures mode is
  intact.
- **Nine of fifteen result files.** Five 112-bit tr-ecdsa cells are partially
  recoverable from `results/report_cl26_gg18.md` and are transcribed — clearly
  marked, and outside the aggregator's search path — in `results/recovered/`.
  They were deliberately *not* written as `results/tr-ecdsa/*.json`: the schema
  mandates `min`/`max` inside every timing object and the report preserved only
  means, so conformant files would require inventing numbers. The four 128-bit
  cells for `(3,1)`, `(3,2)`, `(5,2)` and `(10,5)` have no archival record —
  but, per the section above, they can simply be **re-measured**.

### Resolution: the grid was re-run (2026-09-01)

All fifteen cells were re-measured with `orchestrator/run_grid.sh --skip-build`
against the surviving binaries — **15/15 succeeded**, every output validating
against `result_schema.json`. `results/` again holds a complete campaign, and
`results/summary.{csv,md}` describe all fifteen cells rather than six.

The six surviving July files were moved to `results/archive-2026-07/` (outside
the aggregator's search path) rather than deleted, so July numbers and
September numbers can never be tabulated together across two machine states.

The re-run independently corroborates the lost campaign. This document's prose
retained two figures from cells whose JSON was destroyed, and both reproduce:

| Claim written in July | Re-measured September |
|---|---|
| "~7.7 s" — 128-bit, `n=10,t=5` | **7,677.3 ms** |
| "~695–1155 ms" — `n=3,t=1`, 112→128 | **662.1 → 1,123.6 ms** |

Signing times run a few percent faster overall than in July (machine state), and
the qualitative conclusions are unchanged: tr-ecdsa keygen and setup stay far
cheaper, tss-lib signs markedly faster at every cell, and tss-lib's per-party
Paillier pre-params dominate its setup cost.

### Consequences for the numbers above

The current `results/summary.csv` / `summary.md` are from the September re-run
described above and cover the full fifteen-cell grid, so the "Projects evaluated
so far" section is again backed by complete data.

The measurements are reproducible **from binaries, not from source**: re-running
requires `~/.tss-eval-build/trecdsa/trecdsa-eval`, whose source
(`apps/eval/main.cpp`) no longer exists anywhere. That binary is now a
single-point-of-failure artifact — if it is lost, the tr-ecdsa half of this
harness cannot be rebuilt without rewriting the eval app. Back it up, and treat
rewriting `apps/eval/main.cpp` as outstanding work.

---

## The eval app, rewritten (2026-09-01)

The one piece with no archival copy has been reimplemented from three
independent sources of truth: the surviving binary's CLI, the harness schema,
and `apps/bench/main.cpp`, whose measurement conventions it follows. It is
committed to the TR-ECDSA repo as `apps/eval/main.cpp` behind
`-DTRECDSA_BUILD_EVAL=ON`.

Supporting change: `ObjectSizes` / `Protocol::object_sizes()` were added to the
public API, mirroring the existing `BandwidthStats` / `last_bandwidth()`
pattern. The sizes are sampled from real key material at the end of `run_dkg`
rather than derived from parameters — a CL share's byte length depends on `n`
(through `delta = n!`) and on the value drawn. The serialized-size helpers this
uses (`qfi_size_bytes`, `ecpoint_size_bytes`, `zkaok_size_bytes_estimate`, …)
already existed in `src/compat/bicycl_utils.h`: they were part of the same
commit that added the bench app, written for exactly this purpose.

### Verification against the surviving binary

| Check | Result |
|---|---|
| CLI usage string | byte-identical, including error behaviour |
| Round-1/2/3 bandwidth split | `3760` / `11288` exact; round 3 within noise |
| Round-1 `upper_bound_estimate` tag | reproduced |
| `signature`, `ec_public_key`, `ec_key_share` | 56 / 29 / 28 — exact |
| `enc_public_key` / `enc_key_share` at n=3, 5, 10 | 224/74, 224/75, 226/77 — **exact at all three**, including the n-dependence |
| `enc_ciphertext` | 449 vs the old binary's 450 — see below |
| Schema validation | passes |
| Build under `-Werror`, full test suite | clean, 3/3 pass |

The `enc_ciphertext` byte is not a defect. A QFI coefficient's length depends
on the value drawn, and the quantity ranges over 448–451; the two binaries land
at different points in the draw sequence.

### An implementation finding worth recording

While chasing that byte I established that **`BICYCL::RandGen` is unseeded** —
its default constructor calls `gmp_randinit_default` with no seeding — so every
run of every program in this repo draws the *identical* sequence. Two separate
process invocations printed the same three "random" values.

For benchmarking this is harmless and even convenient: it is why object sizes
are perfectly stable across runs. For anything else it is not, since the
CL-HSM side of key generation — DKG secret keys, encryption randomness, ZK
nonces — is fully deterministic. (The EC-side message and signer-subset
selection in `Utils.h` uses OpenSSL's `RAND_bytes` and *is* properly seeded.)
The repo describes itself as a proof-of-concept, so this may well be
deliberate; it is recorded here because it is invisible from the outside and
would be catastrophic in any deployment.
