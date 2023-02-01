#!/bin/bash
#:
#: name = "build-and-test"
#: variety = "basic"
#: target = "helios"
#: rust_toolchain = "stable"
#: output_rules = [
#:   "/work/debug/*",
#:   "/work/release/*",
#: ]
#: access_repos = [
#:   "oxidecomputer/p4",
#:   "oxidecomputer/softnpu",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

# Temporary fix for Cargo isatty error
curl -Lo /tmp/isattyfix.so 'https://buildomat.eng.oxide.computer/wg/0/artefact/01GQQZ09XNZCV9DKAY87YC6JAA/CakFovx5MsPyjDTXsT0f9qN3Pxh4jm6g754HXheja7CVAEsZ/01GQQZ0KG48F651EJ66FRX28JH/01GQQZ2YSFCWKEH7V3WNBS4M6Z/isattyfix.so'
export LD_PRELOAD_64=/tmp/isattyfix.so

cargo --version
rustc --version

banner "check"
cargo fmt -- --check
cargo clippy -- --deny warnings

banner "build"
ptime -m cargo build
ptime -m cargo build --release

for x in debug release
do
    mkdir -p /work/$x
    cp target/$x/scadm /work/$x/
    cp target/$x/libsidecar_lite.so /work/$x/
done

