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
#: [[publish]]
#: series = "release"
#: name = "libsidecar_lite.so"
#: from_output = "/work/release/libsidecar_lite.so"
#:
#: [[publish]]
#: series = "release"
#: name = "libsidecar_lite.so.sha256.txt"
#: from_output = "/work/release/libsidecar_lite.so.sha256.txt"
#:
#: [[publish]]
#: series = "release"
#: name = "scadm"
#: from_output = "/work/release/scadm"
#:
#: [[publish]]
#: series = "release"
#: name = "scadm.sha256.txt"
#: from_output = "/work/release/scadm.sha256.txt"
#:
#: [[publish]]
#: series = "debug"
#: name = "libsidecar_lite.so"
#: from_output = "/work/debug/libsidecar_lite.so"
#:
#: [[publish]]
#: series = "debug"
#: name = "libsidecar_lite.so.sha256.txt"
#: from_output = "/work/debug/libsidecar_lite.so.sha256.txt"
#:
#: [[publish]]
#: series = "debug"
#: name = "scadm"
#: from_output = "/work/debug/scadm"
#:
#: [[publish]]
#: series = "debug"
#: name = "scadm.sha256.txt"
#: from_output = "/work/debug/scadm.sha256.txt"
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
cargo clippy --all-targets -- --deny warnings

banner "build"
ptime -m cargo build
ptime -m cargo build --release

banner "test"
pushd softnpu
cargo test -- --nocapture
popd

for target in debug release
do
    mkdir -p /work/$target
    for binary in libsidecar_lite.so scadm
    do
        cp target/$target/$binary /work/$target/
        digest -a sha256 /work/$target/$binary > /work/$target/$binary.sha256.txt
    done
done

