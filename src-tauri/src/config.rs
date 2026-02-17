// Paths
pub const INSTALL_DIR: &str = r"C:\Program Files\Grippy";
pub const APP_BIN: &str = "Grippy-desktop.exe";
pub const SERVICE_BIN: &str = "Grippy-posture-service.exe";
pub const INSTALLER_BIN: &str = "Grippy-installer.exe";

// App metadata
pub const APP_NAME: &str = "Grippy";
pub const APP_VERSION: &str = "0.1.0";
pub const PUBLISHER: &str = "Grippy";

// Windows service
pub const SERVICE_NAME: &str = "GrippyPosture";
pub const SERVICE_DISPLAY_NAME: &str = "Grippy Posture Service";
pub const SERVICE_DESCRIPTION: &str = "Evaluates system security posture for Grippy";

// Prerequisites
pub const VCREDIST_URL: &str = "https://aka.ms/vs/17/release/vc_redist.x64.exe";
pub const WEBVIEW2_URL: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
pub const MICROSOFT_SIGNER: &str = "Microsoft Corporation";

// Shortcuts
pub const DESKTOP_LNK: &str = r"C:\Users\Public\Desktop\Grippy.lnk";
pub const START_MENU_LNK: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Grippy.lnk";

// Registry
pub const UNINSTALL_REG_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Grippy";

// Uninstall self delete delay (seconds)
pub const SELF_DELETE_DELAY_SECS: u32 = 2;
