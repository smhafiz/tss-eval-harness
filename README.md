# tss-eval-harness

A cross-implementation benchmark harness for threshold-ECDSA (TSS) protocols.

Different threshold-ECDSA implementations use different round structures,
different homomorphic-encryption backends, and different tuning knobs, which
makes it easy to produce numbers that *look* comparable but aren't. This harness
runs each implementation through the same scenario (party count `n`, threshold
`t`, repeated signing trials), captures timing / bandwidth / object-size /
correctness data in one shared JSON schema, and is explicit — in the schema
itself — about exactly where a side-by-side comparison stops being valid.

The harness implements no cryptography. It builds and drives each target
implementation's own code through a small per-implementation adapter, and treats
the implementation repos as external dependencies checked out elsewhere.

## Implementations under evaluation

| Key | Protocol | Language | Encryption |
|---|---|---|---|
| `tr-ecdsa` | 3-round threshold ECDSA ("CL26") | C++17 | CL-HSM class groups |
| `tss-lib` | GG18, 9 signing rounds | Go | Paillier |

## Layout

```
repos.env             # where the implementation repos live (+ build-dir override)
libs/                 # the two implementations, as pinned git submodules
adapters/tss-lib/     # Go adapter: a tecdsa-eval binary built against bnb-chain/tss-lib
orchestrator/         # grid.tsv (the (n,t) sweep) + run_grid.sh (build-and-run driver)
schema/               # result_schema.json + SCHEMA.md (field reference and caveats)
results/<impl>/*.json # one JSON file per (implementation, security-level, n, t) run
aggregator/           # aggregate.py: results/*.json -> summary.csv + summary.md
```

tr-ecdsa needs no adapter shim here: its eval app lives in the TR-ECDSA repo
itself (`apps/eval`, enabled with `-DTRECDSA_BUILD_EVAL=ON`) and writes the
schema JSON natively. tss-lib had no such tooling, so
[`adapters/tss-lib`](adapters/tss-lib) is a standalone Go module written for
this harness. It builds against the published `bnb-chain/tss-lib/v3 v3.0.0`
module, so this repo's tss-lib half is self-contained; to benchmark a local
tss-lib checkout instead, add a `go.work` as described in
[`adapters/tss-lib/go.mod`](adapters/tss-lib/go.mod).

### Upstream projects

Both implementations are third-party open-source projects. They are vendored
under `libs/` as submodules of private mirrors, pinned to the benchmarked
commits (`76ca73f` and `v3.0.0` / `3f677ff`), and remain under their own
licenses — see LICENSE:

- **tr-ecdsa** — [Jiangjiang-jiang/Three-Round-Multiparty-ECDSA](https://github.com/Jiangjiang-jiang/Three-Round-Multiparty-ECDSA) (MIT).
  It vendors [BICYCL](https://gite.lirmm.fr/crypto/bicycl) as a submodule,
  which is **GPL-3.0-or-later** — relevant if you redistribute built binaries.
- **tss-lib** — [bnb-chain/tss-lib](https://github.com/bnb-chain/tss-lib) (MIT).

## Usage

```bash
# 1. Get the implementation repos. They are submodules under libs/, pinned to
#    the exact commits the committed results were measured against.
#    --recursive matters: TR-ECDSA carries BICYCL as a submodule of its own.
git submodule update --init --recursive

# 2. Build both adapters and sweep the grid.
orchestrator/run_grid.sh                       # full grid, security levels 112 and 128
orchestrator/run_grid.sh --grid=orchestrator/smoke-grid.tsv   # fast 2-row sanity check
orchestrator/run_grid.sh --include-slow-levels                # add 192 and 256
orchestrator/run_grid.sh --skip-build                         # reuse existing binaries

# 3. Turn the accumulated JSON into comparative tables.
python3 aggregator/aggregate.py                # -> results/summary.csv, results/summary.md
```

A failing cell logs to stderr and increments a failure counter rather than
aborting the sweep, so one bad `(n,t)` doesn't cost the rest of the grid.
`aggregate.py` is stdlib-only.

Both adapters build from source: the tss-lib module against the published
`tss-lib v3.0.0`, and `trecdsa-eval` from the TR-ECDSA repo via
`-DTRECDSA_BUILD_EVAL=ON`. To drive a prebuilt binary instead, point
`TRECDSA_EVAL` / `TSSLIB_EVAL` at it and pass `--skip-build`.

## Reading the results

**[`schema/SCHEMA.md`](schema/SCHEMA.md) is the important file.** It documents
every field and carries twelve numbered non-comparability caveats — round
boundaries that don't line up, `enc_*` fields that name different cryptographic
objects in each implementation, `null` meaning *skipped* rather than *instant*,
in-process timings with no network cost, and so on. `aggregate.py` appends that
caveats section verbatim to the bottom of every generated `summary.md`, so no
table can be read out of context of its own limitations.

Two things worth knowing before comparing any two rows:

- **`security.label` is a label, not a strength claim.** tr-ecdsa scales its
  curve and its CL group together, so its label *is* its strength. tss-lib is
  fixed to secp256k1 (128-bit tier) paired with Paillier-2048 (112-bit tier) — a
  mismatched pair capped at **112 effective bits**. The aggregator derives
  `overall_security_bits = min(curve, enc)` per NIST SP 800-57 and reports it
  separately. This is why 112 stays in tr-ecdsa's default sweep: it's the one
  level at which the two are genuinely same-strength.
- **Every result records the implementation repo's git commit**, not this
  harness's. Provenance is "what code was actually benchmarked."

[`HARNESS_REPORT.md`](HARNESS_REPORT.md) has the full design write-up, including
the per-implementation measurement challenges and how each was resolved.
