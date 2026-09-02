# Data recovered from `report_cl26_gg18.md` — NOT measurement output

Nine of the fifteen original result JSONs were lost (see
`../../HARNESS_REPORT.md`, "Reconstruction status"). Only
`results/tr-ecdsa/tr-ecdsa_112_n5_t4_1784313730.json` survived on the tr-ecdsa
side.

`results/report_cl26_gg18.md` preserves the **112-bit tr-ecdsa numbers for all
five grid cells**, so five of the nine lost cells are partially recoverable as
*data*. They are recorded here as CSV rather than as `results/tr-ecdsa/*.json`
on purpose:

- The schema requires `min`, `max` and `stddev` inside every `timing_ms` stats
  object, with no nulls permitted inside it. The report preserved only `mean`
  (and `stddev` for the signing phase). Emitting schema-conformant JSON would
  mean **inventing** the missing min/max values.
- A file under `results/tr-ecdsa/` is picked up by `aggregator/aggregate.py`
  and rendered into `summary.md` indistinguishably from a real adapter run.
  Recovered-from-a-PDF-table numbers must not silently acquire that status.

`aggregate.py` globs only `results/tr-ecdsa/` and `results/tss-lib/`, so nothing
in this directory reaches the generated summaries.

## What is recoverable and what is not

| Field | Recoverable from the report? |
|---|---|
| `timing_ms.*.mean` (setup, dkg, sign, verify) | yes |
| `timing_ms.sign.stddev` | yes |
| `timing_ms.*.min` / `.max` | **no** |
| `timing_ms.setup/dkg/verify.stddev` | **no** |
| `throughput_sig_per_sec` | yes |
| `bandwidth_bytes.total` / `.per_party` | yes |
| `bandwidth_bytes.per_round` (incl. the round-1 `upper_bound_estimate`) | **no** |
| `object_sizes_bytes.*` | yes |
| `correctness.all_signatures_valid` | yes |
| `trials.*` | **no** (the surviving cell used 2/2/8) |
| `git_commit` | inferred: `ac2b168`, from the one surviving tr-ecdsa file |

## The four cells with no recovery path at all

The report covers 112-bit only. The 128-bit tr-ecdsa runs for
`(3,1)`, `(3,2)`, `(5,2)` and `(10,5)` are **entirely lost** — the only trace
anywhere is HARNESS_REPORT.md's prose, which mentions ~7.7 s signing at
128-bit `n=10,t=5` and a ~695–1155 ms range at `n=3,t=1`.

Re-running `orchestrator/run_grid.sh` regenerates all of them properly, once the
TR-ECDSA repo's `apps/eval` is restored.
