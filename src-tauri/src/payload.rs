use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use crate::config;
use crate::log::dlog;

const PAYLOAD: &[u8] = include_bytes!("../resources/app-payload.zip");
const EXPECTED_HASH: &str = env!("PAYLOAD_SHA256");

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

struct DirectoryGuard {
    handle: isize,
}

impl DirectoryGuard {
    fn open_pinned(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
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
        }

        const INVALID_HANDLE: isize = -1;
        const OPEN_EXISTING: u32 = 3;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        const FILE_SHARE_READ: u32 = 1;
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
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FLAG_OPEN_REPARSE_POINT | FLAG_BACKUP_SEMANTICS,
                0,
            )
        };

        if handle == INVALID_HANDLE {
            return Err(format!("Failed to open {} for reparse check", path.display()).into());
        }

        #[repr(C)]
        struct ByHandleFileInfo {
            attributes: u32,
            _pad: [u32; 12],
        }

        let mut info: ByHandleFileInfo = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info as *mut _ as *mut _) };

        if ok == 0 {
            unsafe { close_handle(handle) };
            return Err(format!("Failed to query attributes for {}", path.display()).into());
        }

        if info.attributes & ATTR_REPARSE_POINT != 0 {
            unsafe { close_handle(handle) };
            return Err(format!("{} is a reparse point", path.display()).into());
        }

        Ok(DirectoryGuard { handle })
    }
}

impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        unsafe { close_handle(self.handle) };
    }
}

unsafe fn close_handle(handle: isize) {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CloseHandle(handle: isize) -> i32;
    }
    unsafe { CloseHandle(handle) };
}

fn verify_not_reparse_point(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let guard = DirectoryGuard::open_pinned(path)?;
    drop(guard);
    Ok(())
}

fn extract_zip(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let cursor = std::io::Cursor::new(payload);
    let mut archive = zip::ZipArchive::new(cursor)?;
    dlog!("payload: zip contains {} entries", archive.len());

    if archive.len() > config::MAX_ZIP_ENTRIES {
        return Err(format!(
            "Archive contains {} entries, exceeding limit of {}",
            archive.len(),
            config::MAX_ZIP_ENTRIES,
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

    let _install_dir_guard = DirectoryGuard::open_pinned(install_dir)?;
    dlog!("payload: created and pinned {}", config::INSTALL_DIR);

    let mut pinned_dirs: Vec<DirectoryGuard> = Vec::new();
    let mut total_extracted: u64 = 0;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;

        total_extracted = total_extracted
            .checked_add(file.size())
            .ok_or("Extracted size overflow")?;
        if total_extracted > config::MAX_EXTRACTED_BYTES {
            return Err(format!(
                "Extracted size exceeds {} byte limit",
                config::MAX_EXTRACTED_BYTES
            )
            .into());
        }

        let out_path = match file.enclosed_name() {
            Some(name) => install_dir.join(name),
            None => continue,
        };

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            pinned_dirs.push(DirectoryGuard::open_pinned(&out_path)?);
        } else {
            if let Some(parent) = out_path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                    pinned_dirs.push(DirectoryGuard::open_pinned(parent)?);
                }
            }
            let mut dest = std::fs::File::create(&out_path)?;
            std::io::copy(&mut file, &mut dest)?;
        }
    }

    dlog!("payload: all files extracted ({total_extracted} bytes total)");
    Ok(())
}

pub fn safe_remove_dir(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    remove_dir_recursive(dir, config::MAX_DIRECTORY_DEPTH)
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
