use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::config;
use crate::log::dlog;
use crate::shell;

const PAYLOAD: &[u8] = include_bytes!("../resources/app-payload.zip");
const EXPECTED_HASH: &str = env!("PAYLOAD_SHA256");

const MAX_ZIP_ENTRIES: usize = 10_000;
const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GB

/// Extracts the embedded app-payload.zip (initial install).
pub fn extract() -> Result<(), Box<dyn std::error::Error>> {
    dlog!("payload::extract: payload size={} bytes", PAYLOAD.len());

    use sha2::{Digest, Sha256};
    let actual = Sha256::digest(PAYLOAD);
    let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
    if actual_hex != EXPECTED_HASH {
        return Err(format!(
            "Embedded payload integrity check failed: expected {EXPECTED_HASH}, got {actual_hex}"
        )
        .into());
    }
    dlog!("payload::extract: integrity check passed");

    extract_zip(PAYLOAD)
}

pub fn download_and_install_update() -> Result<(), Box<dyn std::error::Error>> {
    dlog!("update: downloading payload and signature");

    let zip_path = shell::csprng_temp_path("zip")?;
    let sig_path = shell::csprng_temp_path("sig")?;

    let result = download_verify_and_extract(&zip_path, &sig_path);

    let _ = std::fs::remove_file(&zip_path);
    let _ = std::fs::remove_file(&sig_path);

    result
}

fn download_verify_and_extract(
    zip_path: &Path,
    sig_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use ed25519_dalek::Verifier;
    use libcrux_ml_dsa::ml_dsa_87;

    let zip_url = format!("{}/update-payload.zip", config::RELEASE_DOWNLOAD_URL);
    let sig_url = format!("{}/update-payload.zip.sig", config::RELEASE_DOWNLOAD_URL);

    shell::download(&zip_url, zip_path)?;
    shell::download(&sig_url, sig_path)?;
    dlog!("update: downloads complete");

    let sig_content = std::fs::read_to_string(sig_path)?;
    let lines: Vec<&str> = sig_content.lines().collect();
    if lines.len() != 3 {
        return Err("Invalid signature file format".into());
    }

    let expected_hash_hex = lines[0].trim();
    let ed25519_sig_hex = lines[1].trim();
    let mldsa_sig_hex = lines[2].trim();

    let payload = std::fs::read(zip_path)?;
    let actual_hash = blake3::hash(&payload);
    let actual_hash_hex = actual_hash.to_hex();
    if actual_hash_hex.as_str() != expected_hash_hex {
        return Err("Payload integrity check failed".into());
    }
    let digest_bytes = actual_hash.as_bytes();
    dlog!("update: BLAKE3 hash verified");

    let ed_sig_bytes: [u8; 64] = hex::decode(ed25519_sig_hex)?
        .try_into()
        .map_err(|_| "Ed25519 signature must be exactly 64 bytes")?;
    let ed_verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&config::ED25519_PUBLIC_KEY)?;
    let ed_signature = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
    ed_verifying_key
        .verify(digest_bytes, &ed_signature)
        .map_err(|_| "Ed25519 signature verification failed")?;
    dlog!("update: Ed25519 signature verified");

    let mldsa_sig_bytes = hex::decode(mldsa_sig_hex)?;
    let mut mldsa_vk = ml_dsa_87::MLDSA87VerificationKey::zero();
    mldsa_vk
        .as_mut_slice()
        .copy_from_slice(&config::MLDSA87_PUBLIC_KEY);
    let mut mldsa_sig = ml_dsa_87::MLDSA87Signature::zero();
    if mldsa_sig_bytes.len() != mldsa_sig.as_slice().len() {
        return Err("ML-DSA-87 signature size mismatch".into());
    }
    mldsa_sig.as_mut_slice().copy_from_slice(&mldsa_sig_bytes);
    ml_dsa_87::verify(&mldsa_vk, digest_bytes, b"", &mldsa_sig)
        .map_err(|_| "ML-DSA-87 signature verification failed")?;
    dlog!("update: ML-DSA-87 signature verified");

    extract_zip(&payload)
}

fn extract_zip(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(payload);
    let mut archive = zip::ZipArchive::new(cursor)?;
    dlog!("payload: zip contains {} entries", archive.len());

    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(format!(
            "Archive contains {} entries, exceeding limit of {MAX_ZIP_ENTRIES}",
            archive.len()
        )
        .into());
    }

    let install_dir = Path::new(config::INSTALL_DIR);

    if let Some(parent) = install_dir.parent() {
        verify_not_reparse_point(parent)?;
    }

    if install_dir.exists() {
        dlog!("payload: removing existing {}", config::INSTALL_DIR);
        safe_remove_dir(install_dir)?;
    }
    std::fs::create_dir_all(install_dir)?;
    verify_not_reparse_point(install_dir)?;

    dlog!("payload: created {}", config::INSTALL_DIR);

    let mut total_extracted: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        total_extracted = total_extracted
            .checked_add(file.size())
            .ok_or("Extracted size overflow")?;
        if total_extracted > MAX_EXTRACTED_BYTES {
            return Err(
                format!("Extracted size exceeds {} byte limit", MAX_EXTRACTED_BYTES).into(),
            );
        }

        let out_path = match file.enclosed_name() {
            Some(name) => install_dir.join(name),
            None => continue,
        };

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            verify_not_reparse_point(&out_path)?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
                verify_not_reparse_point(parent)?;
            }
            let mut dest = std::fs::File::create(&out_path)?;
            std::io::copy(&mut file, &mut dest)?;
        }
    }

    dlog!("payload: all files extracted ({total_extracted} bytes total)");
    Ok(())
}

fn verify_not_reparse_point(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const u8,
            disposition: u32,
            flags: u32,
            template: isize,
        ) -> isize;
        fn GetFileInformationByHandle(handle: isize, info: *mut ByHandleFileInfo) -> i32;
        fn CloseHandle(handle: isize) -> i32;
    }

    #[repr(C)]
    struct ByHandleFileInfo {
        attributes: u32,
        _creation_time: [u32; 2],
        _last_access_time: [u32; 2],
        _last_write_time: [u32; 2],
        _volume_serial: u32,
        _size_high: u32,
        _size_low: u32,
        _num_links: u32,
        _index_high: u32,
        _index_low: u32,
    }

    const INVALID_HANDLE: isize = -1;
    const OPEN_EXISTING: u32 = 3;
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_SHARE_READ_WRITE_DELETE: u32 = 7;
    const FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const ATTR_REPARSE_POINT: u32 = 0x400;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ_WRITE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FLAG_OPEN_REPARSE_POINT | FLAG_BACKUP_SEMANTICS,
            0,
        )
    };

    if handle == INVALID_HANDLE {
        return Err(format!("Failed to open {} for reparse check", path.display()).into());
    }

    let mut info: ByHandleFileInfo = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    unsafe { CloseHandle(handle) };

    if ok == 0 {
        return Err(format!("Failed to query handle attributes for {}", path.display()).into());
    }

    if info.attributes & ATTR_REPARSE_POINT != 0 {
        return Err(format!("{} is a reparse point", path.display()).into());
    }

    Ok(())
}

pub fn safe_remove_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_DEPTH: u32 = 64;
    remove_dir_recursive(dir, MAX_DEPTH)
}

fn remove_dir_recursive(
    dir: &Path,
    remaining_depth: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    if remaining_depth == 0 {
        return Err("Directory nesting too deep for safe removal".into());
    }

    verify_not_reparse_point(dir)?;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();

        if file_type.is_symlink() && file_type.is_dir() {
            remove_directory_junction(&path)?;
        } else if file_type.is_dir() {
            remove_dir_recursive(&path, remaining_depth - 1)?;
        } else {
            std::fs::remove_file(&path)?;
        }
    }

    std::fs::remove_dir(dir)?;
    Ok(())
}

fn remove_directory_junction(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn RemoveDirectoryW(path: *const u16) -> i32;
    }

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    if unsafe { RemoveDirectoryW(wide.as_ptr()) } == 0 {
        return Err(format!("Failed to remove junction at {}", path.display()).into());
    }
    Ok(())
}
