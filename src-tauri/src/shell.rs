use std::fs::File;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config;
use crate::log::dlog;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const FILE_SHARE_READ: u32 = 0x00000001;

pub struct LockedTempFile {
    path: PathBuf,
    lock: Option<File>,
}

impl LockedTempFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for LockedTempFile {
    fn drop(&mut self) {
        self.lock.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

fn system32_dir() -> PathBuf {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    let mut buf = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 && (len as usize) < buf.len() {
        PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize]))
    } else {
        PathBuf::from(r"C:\Windows\System32")
    }
}

fn windows_dir() -> PathBuf {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    let mut buf = [0u16; 260];
    let len = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
    if len > 0 && (len as usize) < buf.len() {
        PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize]))
    } else {
        PathBuf::from(r"C:\Windows")
    }
}

pub fn silent(program: &str) -> Command {
    debug_assert!(
        Path::new(program).is_absolute(),
        "silent() requires an absolute path, got: {program}"
    );
    let mut cmd = Command::new(program);
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

pub fn system32_command(relative_path: &str) -> Command {
    let mut cmd = Command::new(system32_dir().join(relative_path));
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

pub fn windows_command(relative_path: &str) -> Command {
    let mut cmd = Command::new(windows_dir().join(relative_path));
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd
}

pub fn system32_run_ignore(relative_path: &str, args: &[&str]) {
    let _ = system32_command(relative_path).args(args).output();
}

pub fn powershell_run_ignore(args: &[&str]) {
    let _ = system32_command(r"WindowsPowerShell\v1.0\powershell.exe")
        .args(args)
        .output();
}

pub fn download(url: &str, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let out = dest.to_string_lossy();
    let mut last_error = String::new();
    let mut backoff_ms = config::DOWNLOAD_INITIAL_BACKOFF_MS;

    for attempt in 1..=config::DOWNLOAD_MAX_ATTEMPTS {
        let result = system32_command("curl.exe")
            .args([
                "--tlsv1.2",
                "--proto",
                "=https",
                "-L",
                "--max-redirs",
                config::CURL_MAX_REDIRECTS,
                "-o",
                &*out,
                url,
            ])
            .status();

        match result {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_error = format!("curl exited {:?}", status.code());
            }
            Err(e) => {
                last_error = e.to_string();
            }
        }

        if attempt < config::DOWNLOAD_MAX_ATTEMPTS {
            dlog!(
                "download attempt {}/{} failed ({}), retrying in {backoff_ms}ms",
                attempt,
                config::DOWNLOAD_MAX_ATTEMPTS,
                last_error,
            );
            std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            backoff_ms *= 2;
        }
    }

    let _ = std::fs::remove_file(dest);
    Err(format!(
        "Download failed after {} attempts: {url} ({last_error})",
        config::DOWNLOAD_MAX_ATTEMPTS
    )
    .into())
}

pub fn download_and_verify(
    url: &str,
    extension: &str,
) -> Result<LockedTempFile, Box<dyn std::error::Error>> {
    let path = csprng_temp_path(extension)?;
    download(url, &path)?;

    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&path)?;

    if let Err(e) = verify_authenticode(&path, config::MICROSOFT_SIGNER) {
        drop(lock);
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }

    Ok(LockedTempFile {
        path,
        lock: Some(lock),
    })
}

fn csprng_temp_path(extension: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut bytes = [0u8; 16];
    csprng_fill(&mut bytes)?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let path = std::env::temp_dir().join(format!("{}{hex}.{extension}", config::TEMP_FILE_PREFIX));
    File::create_new(&path)?;
    Ok(path)
}

fn csprng_fill(buf: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: isize, buffer: *mut u8, count: u32, flags: u32) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;

    let len: u32 = buf
        .len()
        .try_into()
        .map_err(|_| "CSPRNG buffer exceeds u32::MAX")?;
    let status =
        unsafe { BCryptGenRandom(0, buf.as_mut_ptr(), len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
    if status != 0 {
        return Err(format!("BCryptGenRandom failed: NTSTATUS 0x{status:08X}").into());
    }
    Ok(())
}

pub fn verify_authenticode(
    path: &Path,
    expected_signer: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[repr(C)]
    struct WintrustFileInfo {
        cb_struct: u32,
        file_path: *const u16,
        file_handle: isize,
        known_subject: *const u8,
    }

    #[repr(C)]
    struct WintrustData {
        cb_struct: u32,
        policy_callback_data: usize,
        sip_client_data: usize,
        ui_choice: u32,
        revocation_checks: u32,
        union_choice: u32,
        p_union: *mut WintrustFileInfo,
        state_action: u32,
        state_data: isize,
        url_reference: *const u16,
        provider_flags: u32,
        ui_context: u32,
        signature_settings: usize,
    }

    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WinVerifyTrust(hwnd: isize, action: *mut [u8; 16], data: *mut WintrustData) -> i32;
    }

    const WTD_UI_NONE: u32 = 2;
    const WTD_REVOKE_WHOLECHAIN: u32 = 1;
    const WTD_CHOICE_FILE: u32 = 1;
    const WTD_STATEACTION_VERIFY: u32 = 1;
    const WTD_STATEACTION_CLOSE: u32 = 2;
    const WTD_REVOCATION_CHECK_CHAIN: u32 = 0x40;

    let mut wintrust_action_generic_verify_v2: [u8; 16] = [
        0x6B, 0xC5, 0xAA, 0x00, 0x44, 0xCD, 0xD0, 0x11, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95,
        0xEE,
    ];

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WintrustFileInfo {
        cb_struct: std::mem::size_of::<WintrustFileInfo>() as u32,
        file_path: wide_path.as_ptr(),
        file_handle: 0,
        known_subject: std::ptr::null(),
    };

    let mut trust_data = WintrustData {
        cb_struct: std::mem::size_of::<WintrustData>() as u32,
        policy_callback_data: 0,
        sip_client_data: 0,
        ui_choice: WTD_UI_NONE,
        revocation_checks: WTD_REVOKE_WHOLECHAIN,
        union_choice: WTD_CHOICE_FILE,
        p_union: &mut file_info,
        state_action: WTD_STATEACTION_VERIFY,
        state_data: 0,
        url_reference: std::ptr::null(),
        provider_flags: WTD_REVOCATION_CHECK_CHAIN,
        ui_context: 0,
        signature_settings: 0,
    };

    let result =
        unsafe { WinVerifyTrust(-1, &mut wintrust_action_generic_verify_v2, &mut trust_data) };

    let signer_result = if result == 0 {
        verify_signer_name(trust_data.state_data, expected_signer)
    } else {
        Ok(())
    };

    trust_data.state_action = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(-1, &mut wintrust_action_generic_verify_v2, &mut trust_data);
    }

    if result != 0 {
        return Err(format!(
            "Authenticode verification failed for {} (0x{:08X})",
            path.display(),
            result as u32
        )
        .into());
    }

    signer_result
}

fn verify_signer_name(state_data: isize, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[link(name = "wintrust")]
    unsafe extern "system" {
        fn WTHelperProvDataFromStateData(state_data: isize) -> *const u8;
        fn WTHelperGetProvSignerFromChain(
            prov_data: *const u8,
            signer_idx: u32,
            counter_signer: i32,
            counter_signer_idx: u32,
        ) -> *const ProviderSgnr;
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CertGetNameStringW(
            cert_context: *const u8,
            name_type: u32,
            flags: u32,
            type_para: *const u8,
            name_string: *mut u16,
            cch_name_string: u32,
        ) -> u32;
    }

    #[repr(C)]
    struct ProviderSgnr {
        _cb_struct: u32,
        _sft_verify_as_of: [u32; 2],
        cert_chain_count: u32,
        cert_chain: *const ProviderCert,
    }

    #[repr(C)]
    struct ProviderCert {
        _cb_struct: u32,
        p_cert: *const u8,
    }

    const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;

    unsafe {
        let prov_data = WTHelperProvDataFromStateData(state_data);
        if prov_data.is_null() {
            return Err("Authenticode state contains no provider data".into());
        }

        let signer = WTHelperGetProvSignerFromChain(prov_data, 0, 0, 0);
        if signer.is_null() {
            return Err("No signer found in Authenticode certificate chain".into());
        }

        if (*signer).cert_chain_count == 0 || (*signer).cert_chain.is_null() {
            return Err("Signer has empty certificate chain".into());
        }

        let cert = (*(*signer).cert_chain).p_cert;
        if cert.is_null() {
            return Err("Signer certificate context is null".into());
        }

        let mut buf = [0u16; 256];
        let len = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );

        if len <= 1 {
            return Err("Failed to extract signer name from certificate".into());
        }

        let name = String::from_utf16_lossy(&buf[..(len - 1) as usize]);
        if name != expected {
            return Err(format!("Signer mismatch: expected \"{expected}\", got \"{name}\"").into());
        }
    }

    Ok(())
}

pub fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ps_single_quote_simple() {
        assert_eq!(ps_single_quote("hello"), "'hello'");
    }

    #[test]
    fn ps_single_quote_with_single_quote() {
        assert_eq!(ps_single_quote("it's"), "'it''s'");
    }

    #[test]
    fn ps_single_quote_multiple_consecutive_quotes() {
        assert_eq!(ps_single_quote("a'''b"), "'a''''''b'");
    }

    #[test]
    fn ps_single_quote_empty() {
        assert_eq!(ps_single_quote(""), "''");
    }

    #[test]
    fn ps_single_quote_path() {
        assert_eq!(
            ps_single_quote(r"C:\Program Files\app.exe"),
            r"'C:\Program Files\app.exe'"
        );
    }

    #[test]
    fn ps_single_quote_injection_attempt() {
        assert_eq!(ps_single_quote("'; rm -rf /; '"), "'''; rm -rf /; '''");
    }

    #[test]
    fn ps_single_quote_double_quotes_passthrough() {
        assert_eq!(ps_single_quote("say \"hi\""), "'say \"hi\"'");
    }

    #[test]
    fn ps_single_quote_dollar_sign() {
        assert_eq!(ps_single_quote("$env:PATH"), "'$env:PATH'");
    }
}
