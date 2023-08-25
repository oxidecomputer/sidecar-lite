# Sidecar Lite

Sidecar lite is a port of the switch P4 code that interconnects the Oxide
platform. This port primarily for running the code in various SoftNpu-based
environments.

This repository contains

- [The sidecar lite p4 code](p4).
- [A softnpu Rust build of sidecar lite](softnpu)
- [A softnpu control plane program for sidecar lite `scadm`](scadm).

## Development

To build the sidecar-lite shared library artifact simply run `cargo build`. If
you are actively working on the p4 code a _much_ better compiler experience is
using the `x4c` CLI compiler, which you can build from the Oxide
[p4](https://github.com/oxidecomputer/p4) repo.

## Use

A good example of using this end-to-end is in this demo.
- https://youtu.be/LnU2qVmlhvw?si=GWZh--hLLzfC-0rb&t=1038
