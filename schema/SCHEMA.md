# Result schema — field reference and comparability caveats

Machine-checkable shape: [result_schema.json](result_schema.json) (JSON Schema
draft-07, `additionalProperties: false` throughout — an adapter that invents a
field fails validation rather than silently smuggling it into the aggregate).

One result file describes exactly one **cell**: one `(implementation,
security-level, n, t)` combination, produced by one adapter run. The
orchestrator writes them to `results/<implementation>/<implementation>_<security
label>_n<n>_t<t>_<unix timestamp>.json`; `aggregator/aggregate.py` reads every
such file and emits `results/summary.csv` and `results/summary.md`.

Both adapters must emit this same shape. Field names are deliberately
**protocol-agnostic** (`enc_*`, not `paillier_*` / `cl_*`) so the schema does
not bake in either implementation's design — but identical field names across
two different protocols are exactly where a careless comparison goes wrong, so
read the caveats in the second half of this file before putting two rows side
by side.

---

## Field reference

### Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `1` | Bumped only on a breaking shape change. The aggregator assumes 1. |
| `implementation` | `"tr-ecdsa"` \| `"tss-lib"` | Which implementation produced the row. Also the `results/` subdirectory name. |
| `protocol_name` | string | Human-readable protocol identity, e.g. `"TR-ECDSA (3-round, CL-HSM)"`, `"GG18 (9-round, Paillier)"`. Display only. |
| `git_commit` | string | Short SHA of the **implementation repo under test**, not of this harness. Provenance is "what code was actually benchmarked"; both targets are moving. |
| `notes` | string | Free text for run-specific qualifications. Empty string, never `null`. Carried verbatim into `summary.csv`. |

### `security`

| Field | Type | Meaning |
|---|---|---|
| `label` | string | The implementation's own name for the level it was asked to run at: tr-ecdsa uses the requested CL security level (`"112"`, `"128"`, `"192"`, `"256"`); tss-lib has no level knob and reports its fixed curve, `"secp256k1"`. **This is a label, not a strength claim** — see caveat 5. |
| `enc_scheme` | string | Homomorphic-encryption backend: `"CL_HSMqk"` or `"Paillier"`. |
| `enc_modulus_bits` | integer \| `null` | Bit length of the encryption modulus where that concept applies (Paillier: 2048). `null` for CL-HSM, whose security comes from class-group order, not a modulus — `null` means *not applicable*, not *unmeasured*. |

### `params`

| Field | Type | Meaning |
|---|---|---|
| `n` | integer ≥ 1 | Total parties in the DKG. |
| `t` | integer ≥ 0 | Threshold in the implementations' own convention: any `t+1` parties can sign. |
| `signers` | integer ≥ 1 | Parties that actually participated in the signing trials — `t+1` in every current cell. |

### `trials`

Sample counts behind the corresponding `timing_ms` entries. A `0` here must be
paired with a `null` there.

| Field | Meaning |
|---|---|
| `setup_trials` | Samples behind `timing_ms.setup`. For tss-lib live mode this is `n` — one Paillier pre-param generation per party (caveat 7). |
| `dkg_trials` | Samples behind `timing_ms.dkg_or_keygen`. `1` for tss-lib: the interactive protocol is run once, so its `stddev` is `0` by construction, not by measurement. |
| `sign_trials` | Repeated signings, fresh random message each trial, fixed signer subset. Default 8. |

### `timing_ms`

Each of `setup`, `dkg_or_keygen`, `sign`, `verify` is either `null` or an object
of `{mean, min, max, stddev}` in **milliseconds**. `stddev` is the population
standard deviation (divisor `N`, not `N-1`), so a single-sample phase reports
`0` rather than being undefined.

| Phase | Meaning |
|---|---|
| `setup` | One-time, pre-protocol parameter generation: tr-ecdsa's CL-HSM group setup; tss-lib's per-party Paillier safe-prime pre-params. **These are not the same kind of work** — caveat 6. |
| `dkg_or_keygen` | The interactive distributed key generation protocol itself, wall-clock from first party start to last party finish. |
| `sign` | One full signing protocol run to a verified signature, wall-clock across all signers. |
| `verify` | Single-signature ECDSA verification, timed in an isolated pass over one already-produced signature — not part of the signing measurement. |

`null` means **the phase was not measured** and must never be read as zero;
see caveat 8.

### `throughput_sig_per_sec`

`1000 / timing_ms.sign.mean`. Sequential single-signature throughput — one
signing operation at a time, no pipelining or batching. Not a server
throughput figure.

### `bandwidth_bytes`

| Field | Type | Meaning |
|---|---|---|
| `total` | integer | Total wire bytes across all parties for **one** signing operation, from one representative trial (not a mean). Keygen bandwidth is not counted here. |
| `per_party` | number | `total / signers`. |
| `per_round` | array | `{round_label, bytes, exactness}` entries. Order is not significant. |
| `per_round_comparable_across_impl` | boolean | `false` in every current cell — see caveat 1. |

`exactness` is the honesty flag on each bucket:

| Value | Meaning |
|---|---|
| `exact` | Byte count of actually serialized wire messages. |
| `upper_bound_estimate` | Computed from a size bound because the object's serialization is not reachable through the library's public API (tr-ecdsa's round-1 ZKAoK proof). The true value is at most this. |
| `sampled` | Extrapolated from a subset of messages rather than counted on every one. |

### `object_sizes_bytes`

Serialized sizes of single objects, sampled from a completed run.

| Field | Meaning |
|---|---|
| `signature` | The ECDSA signature: `R‖S`. |
| `ec_public_key` | The group public key, compressed point encoding. |
| `ec_key_share` | One party's secret EC key share. |
| `enc_public_key` | Public key of the homomorphic encryption scheme. **Different meaning per implementation — caveat 2.** |
| `enc_key_share` | One party's share of / stake in the encryption secret key. **Different meaning per implementation — caveat 3.** |
| `enc_ciphertext` | One homomorphic ciphertext. |

### `correctness`

| Field | Meaning |
|---|---|
| `all_signatures_valid` | `true` only if *every* signature produced across all `sign_trials` verified under the group public key. A `false` row invalidates the timing numbers next to it — a protocol that fails is not "fast". |

### `environment`

`os` (e.g. `"darwin"`), `impl_language` (`"cpp17"`, `"go1.23"`), optional
`impl_build_flags`. Machine identity (CPU, RAM, OS build) is **not** in the
schema — it is recorded once per campaign in the write-up, since every cell in a
grid run comes from the same host. Numbers from different hosts must not be
compared.

---

## Non-comparability caveats

These are numbered and stable; adapter comments and result `notes` fields cite
them by number, and `aggregator/aggregate.py` appends this entire section
verbatim to the bottom of `results/summary.md` so no generated table can be
read out of context of its own limitations. **Do not renumber.**

**1. `per_round` buckets do not line up between implementations.** TR-ECDSA has
three native protocol rounds and reports them as such. tss-lib exposes no round
index on outgoing messages — only a `Type()` string like
`"binance.tsslib.ecdsa.signing.SignRound3Message"` — so the adapter
regex-matches `SignRound(\d+)` out of that string to bucket bytes
(`internal/signrun.go`). That is pattern-matching a message type name, not a
protocol round boundary, and GG18 has nine rounds to TR-ECDSA's three. Every
result therefore sets `per_round_comparable_across_impl: false`. Compare
`bandwidth_bytes.total` across implementations; compare `per_round` only
*within* one implementation.

**2. `enc_public_key` is not the same object in both.** In TR-ECDSA the CL-HSM
public key belongs to a genuinely shared, threshold-ized encryption keypair. In
GG18 there is no shared encryption key at all: each party generates its own
independent Paillier keypair, and this field is one party's individual public
key. Same field name, different cryptographic object.

**3. `enc_key_share` carries a different guarantee in each.** TR-ECDSA's value
is a real share of a secret that no party ever holds in full. GG18 does not
threshold-ize Paillier — each party holds its *entire own* Paillier secret key
and uses it only for local MtA computations, so the "share" is a full key by a
different name. The byte counts are comparable as storage; the security
properties behind them are not.

**4. There is no shared security-level axis.** TR-ECDSA takes an independent CL
security level (112/128/192/256) and scales both its EC curve and its CL-HSM
group from it. tss-lib has no equivalent knob — it is hardwired to secp256k1
with a static Paillier-2048 modulus. Rather than invent a mapping between the
two, the grid sweeps tr-ecdsa's levels independently and repeats the single
tss-lib row once per `(n,t)` in the merged table. A tr-ecdsa row and a tss-lib
row in the same `(n,t)` group are *not* two settings of one axis.

**5. `security.label` is not an honest strength number on its own.** TR-ECDSA's
label is a real strength figure because its curve and its CL group are scaled
together from one requested level. tss-lib's `"secp256k1"` is not: a 256-bit
curve (NIST 128-bit tier) paired with a 2048-bit Paillier modulus (NIST 112-bit
tier) is a *mismatched* pair, and the real-world strength is capped by the
weaker component. `aggregate.py` therefore derives `curve_security_bits`,
`enc_security_bits`, and `overall_security_bits = min(curve, enc)` per row from
NIST SP 800-57 Part 1 Rev. 5 Table 2, and `summary.md` gets a dedicated
"Security strength" table. tss-lib lands at **112 effective bits**. This is why
112 stays in tr-ecdsa's default sweep despite being its weakest tier: it is the
only level at which the two implementations are genuinely same-strength, and
dropping it would remove the one real apples-to-apples point in the grid.

**6. `setup` measures different work in each implementation.** For TR-ECDSA it
is CL-HSM group/parameter setup — tens of milliseconds. For tss-lib it is
per-party Paillier safe-prime generation — seconds, and highly variable
(rejection sampling on random candidates, hence the large `stddev`). Both are
"one-time cost before you can key-generate", which is why they share a field,
but a 30× ratio between them is a statement about two unrelated pieces of
mathematics, not about implementation quality.

**7. tss-lib's `setup` aggregates across parties, not across repeats.** Its
`setup_trials` is `n`: one pre-param generation per party, and the reported
`mean`/`min`/`max`/`stddev` describe the spread *across parties within a single
run*, not repeated measurement of the same quantity. The wall-clock cost of
reaching a key-generatable state is closer to `max` than to `mean` when parties
run in parallel, and closer to the sum when they run serially.

**8. `null` timings mean skipped, never instant.** tss-lib ships precomputed
keygen fixtures for exactly `(n=5, t=2)`; loading them bypasses pre-param
generation and the interactive keygen protocol entirely. In `mode=fixtures`
runs, `timing_ms.setup` and `timing_ms.dkg_or_keygen` are serialized as JSON
`null` with `trials` of `0` — deliberately never `0.0`, so a skipped
measurement cannot be silently averaged in as a fast one. `grid.tsv` marks
exactly one row (`5 2 fixtures`) this way; every other cell runs `mode=live`.
Signing, bandwidth, and object-size numbers from a fixtures row *are* real.

**9. `bandwidth_bytes.total` is one trial, not a mean.** It is taken from a
single representative signing trial (the last one), mirroring TR-ECDSA's
`last_bandwidth()` semantics. Protocol message sizes are near-deterministic, so
trial-to-trial variance is small, but this is not a statistic and has no
error bar.

**10. tss-lib is measured with its full proof set enabled — on purpose.**
tss-lib's own test suite calls `SetNoProofMod()` and `SetNoProofFac()` to skip
expensive ZK proofs for test speed. The adapter deliberately never calls them,
so the numbers reflect the production-representative protocol rather than a
stripped-down test configuration. This makes tss-lib's keygen look slower than
its own test suite suggests. **Do not "fix" this** — it is not an oversight,
and enabling those setters would make every tss-lib keygen number
non-representative.

**11. Timings are in-process, with zero network cost.** Both adapters run all
parties as threads/goroutines in one process and pass messages in memory. There
is no serialization-to-socket, latency, or bandwidth constraint in any timing
number. `bandwidth_bytes` says what *would* cross a network; `timing_ms` does
not include the cost of it crossing. Round count matters enormously in a real
deployment and barely at all here — which systematically favours the
higher-round protocol (GG18, 9 rounds) in these measurements.

**12. `throughput_sig_per_sec` is sequential and single-key.** It is the
reciprocal of mean signing latency, not a measured concurrent throughput. No
batching, no pipelining across signing sessions, no multiple key shares in
flight. Treat it as a restatement of `sign.mean`, not as a capacity figure.
