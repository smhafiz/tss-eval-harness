# CL26 vs GG18 comparison (112-bit security)

## Evaluation setup

**Machine:** **Apple M2 Max, 12 cores, 32 GB RAM, macOS 26.5.2 (Darwin 25.5.0, arm64)**. 

| | CL26 | GG18 |
|---|---|---|
| Language | C++17 | Go 1.23 |
| Key dependencies | CMake build; BICYCL (bundled class-group library); GMP + GMPXX (`find_library(... REQUIRED)`); OpenSSL (`find_package(OpenSSL REQUIRED)`) | `github.com/bnb-chain/tss-lib/v3 v3.0.0` (module `go.mod` in `adapters/tss-lib`), plus its transitive deps: `decred/dcrd/dcrec/secp256k1`, `btcsuite/btcd`, `gogo/protobuf`, `google.golang.org/protobuf`, `go.uber.org/zap`, `golang.org/x/crypto` |



## Timing & throughput

| n | t | Impl | Setup (ms) | DKG/Keygen (ms) | Sign (ms) | ±σ (ms) | Verify (ms) | Throughput (sig/s) |
|---|---|---|---|---|---|---|---|---|
| 3 | 1 | CL26 | 149.2 | 34.0 | 694.6 | 5.9 | 0.127 | 1.44 |
| 3 | 1 | GG18 | 4,042.2 | 2,318.2 | 169.4 | 3.2 | 0.162 | 5.90 |
| 3 | 2 | CL26 | 148.2 | 34.0 | 1,308.9 | 21.5 | 0.183 | 0.76 |
| 3 | 2 | GG18 | 4,751.7 | 2,190.3 | 281.9 | 7.9 | 0.176 | 3.55 |
| 5 | 2 | CL26 | 145.6 | 48.2 | 1,368.5 | 10.5 | 0.184 | 0.73 |
| 5 | 2 | GG18 | — | — | 298.3 | 12.0 | 0.162 | 3.35 |
| 5 | 4 | CL26 | 138.4 | 50.2 | 3,410.8 | 8.6 | 0.332 | 0.29 |
| 5 | 4 | GG18 | 4,189.8 | 3,703.1 | 761.2 | 8.4 | 0.172 | 1.31 |
| 10 | 5 | CL26 | 135.8 | 86.4 | 4,507.1 | 45.6 | 0.364 | 0.22 |
| 10 | 5 | GG18 | 3,687.8 | 12,195.7 | 1,115.4 | 9.6 | 0.167 | 0.90 |

## Bandwidth (one signing operation)

| n | t | Impl | Total (B) | Per-party (B) |
|---|---|---|---|---|
| 3 | 1 | CL26 | 9,317 | 4,658 |
| 3 | 1 | GG18 | 21,414 | 10,707 |
| 3 | 2 | CL26 | 13,967 | 4,656 |
| 3 | 2 | GG18 | 59,691 | 19,897 |
| 5 | 2 | CL26 | 13,976 | 4,659 |
| 5 | 2 | GG18 | 59,694 | 19,898 |
| 5 | 4 | CL26 | 23,295 | 4,659 |
| 5 | 4 | GG18 | 191,398 | 38,280 |
| 10 | 5 | CL26 | 27,935 | 4,656 |
| 10 | 5 | GG18 | 284,822 | 47,470 |

## Object sizes (bytes)

| n | t | Impl | Sig | EC PK | EC share | Enc PK | Enc share | Enc ctext |
|---|---|---|---|---|---|---|---|---|
| 3 | 1 | CL26 | 56 | 29 | 28 | 224 | 74 | 450 |
| 3 | 1 | GG18 | 64 | 33 | 32 | 256 | 256 | 512 |
| 3 | 2 | CL26 | 56 | 29 | 28 | 224 | 74 | 450 |
| 3 | 2 | GG18 | 64 | 33 | 32 | 256 | 256 | 512 |
| 5 | 2 | CL26 | 56 | 29 | 28 | 224 | 75 | 450 |
| 5 | 2 | GG18 | 64 | 33 | 32 | 256 | 256 | 512 |
| 5 | 4 | CL26 | 56 | 29 | 28 | 224 | 75 | 450 |
| 5 | 4 | GG18 | 64 | 33 | 32 | 256 | 256 | 512 |
| 10 | 5 | CL26 | 56 | 29 | 28 | 226 | 77 | 450 |
| 10 | 5 | GG18 | 64 | 33 | 32 | 256 | 256 | 512 |

## Correctness

| n | t | Impl | All signatures valid |
|---|---|---|---|
| 3 | 1 | CL26 | yes |
| 3 | 1 | GG18 | yes |
| 3 | 2 | CL26 | yes |
| 3 | 2 | GG18 | yes |
| 5 | 2 | CL26 | yes |
| 5 | 2 | GG18 | yes |
| 5 | 4 | CL26 | yes |
| 5 | 4 | GG18 | yes |
| 10 | 5 | CL26 | yes |
| 10 | 5 | GG18 | yes |

## Acronyms

| Acronym | Full form |
|---|---|
| CL26 | Three-Round-Multiparty-ECDSA — a 3-round threshold-ECDSA protocol (also referred to in the schema as TR-ECDSA) built on CL-HSM class-group encryption |
| GG18 | Gennaro–Goldfeder 2018 — the threshold-ECDSA protocol (9 signing rounds, Paillier encryption) implemented by bnb-chain/tss-lib |
| DKG | Distributed Key Generation |
| EC | Elliptic Curve |
| PK | Public Key |
| Sig | Signature |
| Enc | Encryption |
| ctext | Ciphertext |
