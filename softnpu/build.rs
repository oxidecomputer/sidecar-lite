fn main() {
    let src = [
        "../p4/sidecar-lite.p4",
        "../p4/core.p4",
        "../p4/softnpu.p4",
        "../p4/headers.p4",
    ];
    for x in src {
        println!("cargo:rerun-if-changed={x}");
    }
}
