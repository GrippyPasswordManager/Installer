use sha2::{Digest, Sha256};
use std::io::Read;

fn main() {
    tauri_build::build();
    let payload_path = std::path::Path::new("resources/app-payload.zip");
    let mut file =
        std::fs::File::open(payload_path).expect("resources/app-payload.zip must exist to build");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .expect("failed to read resources/app-payload.zip");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    assert!(!hex.is_empty());
    println!("cargo:rustc-env=PAYLOAD_SHA256={hex}");
    println!("cargo:rerun-if-changed=resources/app-payload.zip");
}
