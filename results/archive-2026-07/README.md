# The surviving files from the original 2026-07-17 campaign

These are the six genuine result files that survived the data loss (five
tss-lib, one tr-ecdsa), plus the summaries regenerated from just those six.
They are the only measurements from the original campaign that still exist as
schema-conformant JSON.

Moved out of `results/tr-ecdsa/` and `results/tss-lib/` — and so out of
`aggregator/aggregate.py`'s search path — before the re-run, so that July
numbers and the re-run's numbers can never land in one summary table. They were
taken on a different machine state (the (5,4) cell reproduced ~12% faster in
September), so averaging or tabulating across the two would be comparing
machine conditions, not implementations.

Nothing here was deleted; if the re-run needs to be abandoned, moving these
back restores the previous state exactly.
