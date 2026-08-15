use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=TDREPORT_TDVF_PATH");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must set CARGO_MANIFEST_DIR"),
    );
    let source = env::var_os("TDREPORT_TDVF_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("assets/td-shim-tdreport.bin"));
    println!("cargo:rerun-if-changed={}", source.display());

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"))
        .join("td-shim-tdreport.bin");
    fs::copy(&source, &output).unwrap_or_else(|error| {
        panic!(
            "failed to copy TDVF image {} to {}: {error}",
            source.display(),
            output.display()
        )
    });
}
