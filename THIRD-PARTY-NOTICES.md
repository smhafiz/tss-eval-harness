# Third-party notices

`tss-eval-harness` itself is MIT licensed — see [LICENSE](LICENSE).

This repository contains no third-party source code. It references the
following independently-licensed projects, each of which remains under its own
license.

## bnb-chain/tss-lib — MIT

Resolved as a Go module dependency by [`adapters/tss-lib`](adapters/tss-lib),
and pinned as a submodule at `libs/tss-lib` (`v3.0.0`, `3f677ff`). Used
unmodified; its source is not vendored here.

<https://github.com/bnb-chain/tss-lib>

## Three-Round-Multiparty-ECDSA — MIT

Built from `libs/Three-Round-Multiparty-ECDSA`, a fork of
<https://github.com/Jiangjiang-jiang/Three-Round-Multiparty-ECDSA> pinned at
`17bb21b`. The orchestrator executes its `trecdsa-eval` binary as a subprocess.

The fork adds the bandwidth and object-size instrumentation the harness reads,
plus the `trecdsa-eval` app itself; none of that exists upstream, which is why
the harness cannot measure an unmodified checkout.

## BICYCL — GNU GPL v3.0 or later

<https://gite.lirmm.fr/crypto/bicycl>

A submodule of Three-Round-Multiparty-ECDSA, reached only through that project.
No BICYCL source is present in this repository.

**A `trecdsa-eval` binary links BICYCL and is therefore subject to the GPL.**
That obligation attaches to such binaries, not to the source in this
repository. If you redistribute a built `trecdsa-eval`, you take on the GPL's
requirements for it.
