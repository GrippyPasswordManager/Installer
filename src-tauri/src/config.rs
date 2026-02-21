pub const INSTALL_DIR: &str = r"C:\Program Files\Grippy";
pub const APP_BIN: &str = "Grippy-desktop.exe";
pub const SERVICE_BIN: &str = "Grippy-posture-service.exe";
pub const INSTALLER_BIN: &str = "Grippy-installer.exe";

pub const APP_NAME: &str = "Grippy";
pub const APP_VERSION: &str = "0.1.0";
pub const PUBLISHER: &str = "Grippy";

pub const SERVICE_NAME: &str = "GrippyPosture";
pub const SERVICE_DISPLAY_NAME: &str = "Grippy Posture Service";
pub const SERVICE_DESCRIPTION: &str = "Evaluates system security posture for Grippy";
pub const SERVICE_POLL_INTERVAL_MS: u64 = 250;
pub const SERVICE_TEARDOWN_TIMEOUT_SECS: u64 = 10;
pub const SERVICE_FAILURE_RESET_SECS: u32 = 86400;
pub const SERVICE_FIRST_FAILURE_RESTART_MS: u32 = 5000;
pub const SERVICE_SECOND_FAILURE_RESTART_MS: u32 = 10000;

pub const VCREDIST_URL: &str = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
pub const VCREDIST_EXIT_ALREADY_INSTALLED: i32 = 1638;
pub const VCREDIST_EXIT_REBOOT_REQUIRED: i32 = 3010;
pub const VCREDIST_MIN_MAJOR_VERSION: u32 = 14;

pub const WEBVIEW2_URL: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
pub const WEBVIEW2_RUNTIME_GUID: &str = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
pub const WEBVIEW2_NULL_VERSION: &str = "0.0.0.0";

pub const MICROSOFT_SIGNER: &str = "Microsoft Corporation";

pub const DESKTOP_LNK: &str = r"C:\Users\Public\Desktop\Grippy.lnk";
pub const START_MENU_LNK: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Grippy.lnk";

pub const UNINSTALL_REG_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Grippy";
pub const SELF_DELETE_DELAY_SECS: u32 = 2;

pub const DOWNLOAD_MAX_ATTEMPTS: u32 = 3;
pub const DOWNLOAD_INITIAL_BACKOFF_MS: u64 = 1000;
pub const CURL_MAX_REDIRECTS: &str = "5";
pub const TEMP_FILE_PREFIX: &str = "grippy_";

pub const MAX_ZIP_ENTRIES: usize = 10_000;
pub const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_DIRECTORY_DEPTH: u32 = 64;

pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;
pub const MAX_LOG_AGE_SECS: u64 = 30 * 24 * 60 * 60;
pub const SANITIZE_MAX_LENGTH: usize = 4096;

pub const KILL_APP_SETTLE_MS: u64 = 500;
pub const LAUNCH_SETTLE_MS: u64 = 300;

use std::path::{Path, PathBuf};

pub fn install_dir() -> &'static Path {
    Path::new(INSTALL_DIR)
}

pub fn app_path() -> PathBuf {
    install_dir().join(APP_BIN)
}

pub fn service_path() -> PathBuf {
    install_dir().join(SERVICE_BIN)
}

pub fn installer_path() -> PathBuf {
    install_dir().join(INSTALLER_BIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_path_ends_with_bin() {
        assert!(app_path().ends_with(APP_BIN));
    }

    #[test]
    fn service_path_ends_with_bin() {
        assert!(service_path().ends_with(SERVICE_BIN));
    }

    #[test]
    fn installer_path_ends_with_bin() {
        assert!(installer_path().ends_with(INSTALLER_BIN));
    }

    #[test]
    fn all_paths_start_with_install_dir() {
        let dir = install_dir();
        assert!(app_path().starts_with(dir));
        assert!(service_path().starts_with(dir));
        assert!(installer_path().starts_with(dir));
    }

    #[test]
    fn install_dir_is_absolute() {
        assert!(install_dir().is_absolute());
    }

    #[test]
    fn timeout_constants_positive() {
        assert!(SERVICE_POLL_INTERVAL_MS > 0);
        assert!(SERVICE_TEARDOWN_TIMEOUT_SECS > 0);
        assert!(KILL_APP_SETTLE_MS > 0);
        assert!(LAUNCH_SETTLE_MS > 0);
        assert!(DOWNLOAD_INITIAL_BACKOFF_MS > 0);
    }

    #[test]
    fn limit_constants_reasonable() {
        assert!(DOWNLOAD_MAX_ATTEMPTS >= 1 && DOWNLOAD_MAX_ATTEMPTS <= 10);
        assert!(MAX_ZIP_ENTRIES > 0 && MAX_ZIP_ENTRIES <= 100_000);
        assert!(MAX_EXTRACTED_BYTES > 0);
        assert!(MAX_DIRECTORY_DEPTH > 0 && MAX_DIRECTORY_DEPTH <= 256);
        assert!(MAX_LOG_BYTES > 0);
        assert!(MAX_LOG_AGE_SECS > 0);
        assert!(SANITIZE_MAX_LENGTH > 0);
    }

    #[test]
    fn service_failure_constants_reasonable() {
        assert!(SERVICE_FAILURE_RESET_SECS > 0);
        assert!(SERVICE_FIRST_FAILURE_RESTART_MS > 0);
        assert!(SERVICE_SECOND_FAILURE_RESTART_MS >= SERVICE_FIRST_FAILURE_RESTART_MS);
    }

    #[test]
    fn urls_are_https() {
        assert!(VCREDIST_URL.starts_with("https://"));
        assert!(WEBVIEW2_URL.starts_with("https://"));
    }

    #[test]
    fn binaries_have_exe_extension() {
        assert!(APP_BIN.ends_with(".exe"));
        assert!(SERVICE_BIN.ends_with(".exe"));
        assert!(INSTALLER_BIN.ends_with(".exe"));
    }
}
