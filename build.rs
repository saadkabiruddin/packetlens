// Finds the Npcap SDK for `--features live` on Windows, so $env:LIB doesn't need setting.
// Set NPCAP_SDK to the SDK folder, or extract it as npcap-sdk-* in the project root.
use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK");
    if env::var_os("CARGO_FEATURE_LIVE").is_none() || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sdk = env::var_os("NPCAP_SDK").map(PathBuf::from).or_else(|| {
        let mut found: Vec<PathBuf> = std::fs::read_dir(&root).ok()?.flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("npcap-sdk") && e.path().is_dir())
            .map(|e| e.path()).collect();
        found.sort();
        found.pop() // newest version by name
    });
    let Some(sdk) = sdk else {
        println!("cargo:warning=Npcap SDK not found; set NPCAP_SDK or extract it to npcap-sdk-<version> in the project folder");
        return;
    };
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "ARM64",
        _ => "",
    };
    let lib = sdk.join("Lib").join(arch);
    println!("cargo:rerun-if-changed={}", lib.display());
    println!("cargo:rustc-link-search=native={}", lib.display());
}
