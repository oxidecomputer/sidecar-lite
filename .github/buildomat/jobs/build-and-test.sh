#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios-latest"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

uname -a
cat /etc/versions/build

cargo --version
rustc --version

banner "check"
cargo fmt -- --check
cargo clippy -- --deny warnings

banner "build"
ptime -m cargo build
ptime -m cargo build --release

banner "test"
pushd softnpu
cargo test -- --nocapture
popd

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/scadm /work/$x/
    cp target/$x/libsidecar_lite.so /work/$x/
done

