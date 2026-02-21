mod config;
pub mod log;
mod payload;
mod prerequisites;
mod registry;
mod service;
mod shell;
mod shortcuts;

use log::dlog;
use tauri::Emitter;

pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            dlog!("is_elevated: OpenProcessToken failed");
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut len,
        );
        let _ = CloseHandle(token);
        if ok.is_err() {
            dlog!("is_elevated: GetTokenInformation failed");
            return false;
        }
        let elevated = elevation.TokenIsElevated != 0;
        dlog!("is_elevated: {elevated}");
        elevated
    }
}

fn quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if !s.contains(|c: char| " \t\"".contains(c)) {
        return s.to_string();
    }
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let mut num_backslashes = 0;
        while i < chars.len() && chars[i] == '\\' {
            num_backslashes += 1;
            i += 1;
        }
        if i == chars.len() {
            for _ in 0..num_backslashes * 2 {
                result.push('\\');
            }
            break;
        } else if chars[i] == '"' {
            for _ in 0..num_backslashes * 2 + 1 {
                result.push('\\');
            }
            result.push('"');
            i += 1;
        } else {
            for _ in 0..num_backslashes {
                result.push('\\');
            }
            result.push(chars[i]);
            i += 1;
        }
    }
    result.push('"');
    result
}

pub fn self_elevate() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    dlog!("self_elevate: exe={}", exe.display());
    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let args: String = std::env::args()
        .skip(1)
        .filter(|a| a == "--uninstall")
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    dlog!("self_elevate: forwarding args=\"{args}\"");
    let args_wide: Vec<u16> = args.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC,
        lpVerb: windows::core::w!("runas"),
        lpFile: PCWSTR(exe_wide.as_ptr()),
        lpParameters: PCWSTR(args_wide.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    unsafe {
        match ShellExecuteExW(&mut sei) {
            Ok(()) => {
                dlog!("self_elevate: ShellExecuteExW succeeded");
                Ok(())
            }
            Err(e) => {
                dlog!("self_elevate: ShellExecuteExW failed: {e}");
                Err(format!("ShellExecuteExW failed: {e}"))
            }
        }
    }
}

pub fn show_error_msgbox(msg: &str) {
    use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    use windows::core::HSTRING;

    let wide_msg = HSTRING::from(msg);
    let wide_title = HSTRING::from("Grippy Installer");
    unsafe {
        MessageBoxW(None, &wide_msg, &wide_title, MB_OK | MB_ICONERROR);
    }
}

struct OwnedMutex(isize);

impl Drop for OwnedMutex {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CloseHandle(handle: isize) -> i32;
        }
        unsafe {
            CloseHandle(self.0);
        }
    }
}

unsafe impl Send for OwnedMutex {}
unsafe impl Sync for OwnedMutex {}

static INSTALL_MUTEX: std::sync::OnceLock<OwnedMutex> = std::sync::OnceLock::new();

fn acquire_install_mutex() -> Result<(), String> {
    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut u8,
        inherit_handle: i32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(
            attrs: *const SecurityAttributes,
            initial_owner: i32,
            name: *const u16,
        ) -> isize;
        fn GetLastError() -> u32;
        fn CloseHandle(handle: isize) -> i32;
        fn LocalFree(mem: *mut u8) -> *mut u8;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_sd: *const u16,
            revision: u32,
            sd: *mut *mut u8,
            sd_size: *mut u32,
        ) -> i32;
    }

    const ERROR_ALREADY_EXISTS: u32 = 183;
    const SDDL_REVISION_1: u32 = 1;

    let name = windows::core::w!("Global\\GrippyInstaller");
    let sddl = windows::core::w!("D:(A;;GA;;;BA)(A;;GA;;;SY)");

    unsafe {
        let mut sd: *mut u8 = std::ptr::null_mut();
        let sd_ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        );
        if sd_ok == 0 {
            return Err("Mutex SDDL security descriptor conversion failed".into());
        }

        let sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: sd,
            inherit_handle: 0,
        };

        let handle = CreateMutexW(&sa, 1, name.as_ptr());
        let last_error = GetLastError();

        if !sd.is_null() {
            LocalFree(sd);
        }

        if handle == 0 {
            dlog!("acquire_install_mutex: CreateMutexW failed: Win32 error {last_error}");
            return Err(format!("Mutex creation failed: Win32 error {last_error}"));
        }
        if last_error == ERROR_ALREADY_EXISTS {
            CloseHandle(handle);
            dlog!("acquire_install_mutex: mutex already held, another install in progress");
            return Err("Another installation is already in progress.".into());
        }
        let _ = INSTALL_MUTEX.set(OwnedMutex(handle));
        dlog!("acquire_install_mutex: acquired with restricted ACL");
    }
    Ok(())
}

fn allowlist_cfa() {
    let arg = format!(
        "Add-MpPreference -ControlledFolderAccessAllowedApplications {},{} -ErrorAction SilentlyContinue",
        shell::ps_single_quote(&config::service_path().to_string_lossy()),
        shell::ps_single_quote(&config::app_path().to_string_lossy()),
    );

    dlog!("allowlist_cfa: {arg}");
    shell::powershell_run_ignore(&["-NoProfile", "-Command", &arg]);
}

fn emit_progress(app: &tauri::AppHandle, msg: &str) {
    dlog!("progress: {msg}");
    let _ = app.emit("install-progress", msg);
}

fn kill_running_app() {
    let app_path = config::app_path();
    dlog!("kill_running_app: killing {}", app_path.display());
    let script = format!(
        "Get-Process | Where-Object {{ $_.Path -eq {} }} | Stop-Process -Force -ErrorAction SilentlyContinue",
        shell::ps_single_quote(&app_path.to_string_lossy())
    );
    shell::powershell_run_ignore(&["-NoProfile", "-Command", &script]);
    std::thread::sleep(std::time::Duration::from_millis(config::KILL_APP_SETTLE_MS));
}

#[tauri::command]
fn log_js_error(msg: String) {
    dlog!("JS ERROR: {}", log::sanitize(&msg));
}

fn fail_install<T>(
    result: Result<T, Box<dyn std::error::Error>>,
    user_message: &str,
) -> Result<T, String> {
    result.map_err(|e| {
        dlog!("{user_message}: {e}");
        user_message.into()
    })
}

fn check_prerequisite(
    app: &tauri::AppHandle,
    result: Result<bool, Box<dyn std::error::Error>>,
    found_msg: &str,
    installed_msg: &str,
) -> Result<(), String> {
    let already_present = fail_install(result, "Failed to install required components.")?;
    emit_progress(
        app,
        if already_present {
            found_msg
        } else {
            installed_msg
        },
    );
    Ok(())
}

struct InstallGuard {
    extracted_files: bool,
    added_cfa_allowlist: bool,
    registered_service: bool,
    created_shortcuts: bool,
    registered_uninstaller: bool,
}

impl InstallGuard {
    fn new() -> Self {
        Self {
            extracted_files: false,
            added_cfa_allowlist: false,
            registered_service: false,
            created_shortcuts: false,
            registered_uninstaller: false,
        }
    }

    fn disarm(&mut self) {
        self.extracted_files = false;
        self.added_cfa_allowlist = false;
        self.registered_service = false;
        self.created_shortcuts = false;
        self.registered_uninstaller = false;
    }
}

impl Drop for InstallGuard {
    fn drop(&mut self) {
        if self.registered_uninstaller {
            dlog!("rollback: removing uninstaller registry");
            registry::remove_uninstaller();
        }
        if self.created_shortcuts {
            dlog!("rollback: removing shortcuts");
            shortcuts::remove();
        }
        if self.registered_service {
            dlog!("rollback: tearing down service");
            let _ = service::teardown_existing();
        }
        if self.added_cfa_allowlist {
            dlog!("rollback: removing CFA allowlist");
            remove_cfa_allowlist();
        }
        if self.extracted_files {
            dlog!("rollback: removing installed files");
            if let Err(e) = payload::safe_remove_dir(config::install_dir()) {
                dlog!("rollback: safe_remove_dir failed: {e}");
            }
        }
    }
}

#[tauri::command]
async fn install(app: tauri::AppHandle) -> Result<(), String> {
    dlog!("install command invoked");

    if !is_elevated() {
        dlog!("ERROR: install command running without elevation");
        return Err(
            "Internal error: installer is not running with administrator privileges.".into(),
        );
    }

    acquire_install_mutex()?;

    emit_progress(&app, "Checking C++ Runtime...");
    check_prerequisite(
        &app,
        prerequisites::ensure_vcredist(),
        "C++ Runtime found",
        "C++ Runtime installed",
    )?;

    emit_progress(&app, "Checking WebView2...");
    check_prerequisite(
        &app,
        prerequisites::ensure_webview2(),
        "WebView2 found",
        "WebView2 installed",
    )?;

    emit_progress(&app, "Preparing installation...");
    fail_install(
        service::teardown_existing(),
        "Failed to prepare for installation.",
    )?;
    dlog!("Service teardown complete");

    kill_running_app();

    let mut guard = InstallGuard::new();

    emit_progress(&app, "Extracting files...");
    fail_install(payload::extract(), "Failed to extract application files.")?;
    guard.extracted_files = true;
    dlog!("Payload extracted to {}", config::INSTALL_DIR);

    allowlist_cfa();
    guard.added_cfa_allowlist = true;

    emit_progress(&app, "Starting service...");
    fail_install(
        service::register_and_start(),
        "Failed to configure application service.",
    )?;
    guard.registered_service = true;
    dlog!("Service registered and started");

    emit_progress(&app, "Creating shortcuts...");
    fail_install(shortcuts::create(), "Failed to create shortcuts.")?;
    guard.created_shortcuts = true;
    dlog!("Shortcuts created");

    emit_progress(&app, "Finalizing...");
    fail_install(
        registry::register_uninstaller(),
        "Failed to finalize installation.",
    )?;
    guard.registered_uninstaller = true;
    dlog!("Uninstaller registered");

    guard.disarm();
    dlog!("Install complete");

    emit_progress(&app, "Launching Grippy...");
    let app_path = config::app_path();
    dlog!(
        "Spawning {} via explorer.exe (de-elevate)",
        app_path.display()
    );

    match shell::windows_command("explorer.exe")
        .arg(&app_path)
        .spawn()
    {
        Ok(_) => dlog!("App launch dispatched via explorer.exe"),
        Err(e) => {
            dlog!("Launch via explorer.exe failed: {e}");
            return Err(
                "Installation completed successfully, but Grippy could not be launched automatically. You can start it from the desktop shortcut."
                    .into(),
            );
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(config::LAUNCH_SETTLE_MS));
    app.exit(0);
    Ok(())
}

fn remove_cfa_allowlist() {
    let arg = format!(
        "Remove-MpPreference -ControlledFolderAccessAllowedApplications {},{} -ErrorAction SilentlyContinue",
        shell::ps_single_quote(&config::service_path().to_string_lossy()),
        shell::ps_single_quote(&config::app_path().to_string_lossy()),
    );

    dlog!("remove_cfa_allowlist: {arg}");
    shell::powershell_run_ignore(&["-NoProfile", "-Command", &arg]);
}

pub fn uninstall() {
    dlog!("uninstall() started");
    kill_running_app();
    if let Err(e) = service::teardown_existing() {
        dlog!("Service teardown failed during uninstall: {e}");
    }
    dlog!("Service torn down");
    remove_cfa_allowlist();
    dlog!("CFA allowlist removed");
    shortcuts::remove();
    dlog!("Shortcuts removed");
    registry::remove_uninstaller();
    dlog!("Registry cleaned");

    let target = shell::ps_single_quote(config::INSTALL_DIR);
    let delay = config::SELF_DELETE_DELAY_SECS;
    let script = format!(
        "$r = 0; while ((Test-Path -LiteralPath {target}) -and ($r -lt 10)) {{ Start-Sleep {delay}; Remove-Item -LiteralPath {target} -Recurse -Force -ErrorAction SilentlyContinue; $r++ }}"
    );
    let _ = shell::system32_command(r"WindowsPowerShell\v1.0\powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .spawn();
    dlog!("Self-delete scheduled");
}

#[tauri::command]
fn exit_app(app: tauri::AppHandle) {
    dlog!("exit_app called");
    app.exit(1);
}

fn is_webview2_in_registry() -> bool {
    use winreg::RegKey;
    use winreg::enums::*;

    let reg_paths = [
        (
            "HKLM WOW64",
            HKEY_LOCAL_MACHINE,
            format!(
                r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{}",
                config::WEBVIEW2_RUNTIME_GUID
            ),
        ),
        (
            "HKLM",
            HKEY_LOCAL_MACHINE,
            format!(
                r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{}",
                config::WEBVIEW2_RUNTIME_GUID
            ),
        ),
        (
            "HKCU",
            HKEY_CURRENT_USER,
            format!(
                r"Software\Microsoft\EdgeUpdate\Clients\{}",
                config::WEBVIEW2_RUNTIME_GUID
            ),
        ),
    ];

    for (label, root, path) in &reg_paths {
        match RegKey::predef(*root).open_subkey(path) {
            Ok(key) => match key.get_value::<String, _>("pv") {
                Ok(v) => {
                    dlog!("WebView2 registry [{label}]: pv=\"{v}\"");
                    if !v.is_empty() && v != config::WEBVIEW2_NULL_VERSION {
                        return true;
                    }
                }
                Err(e) => dlog!("WebView2 registry [{label}]: pv read error: {e}"),
            },
            Err(e) => dlog!("WebView2 registry [{label}]: key not found: {e}"),
        }
    }

    false
}

fn is_webview2_on_disk() -> bool {
    let mut disk_paths: Vec<std::path::PathBuf> = vec![
        std::path::PathBuf::from(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application"),
        std::path::PathBuf::from(r"C:\Program Files\Microsoft\EdgeWebView\Application"),
        std::path::PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application"),
        std::path::PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application"),
    ];
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        disk_paths
            .push(std::path::PathBuf::from(&local).join(r"Microsoft\EdgeWebView\Application"));
        disk_paths.push(std::path::PathBuf::from(&local).join(r"Microsoft\Edge\Application"));
    }

    for dir in &disk_paths {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with(|c: char| c.is_ascii_digit()) {
                let exe = entry.path().join("msedgewebview2.exe");
                if exe.exists() {
                    dlog!("WebView2 found on disk: {}", exe.display());
                    return true;
                }
            }
        }
    }

    false
}

pub fn is_webview2_present() -> bool {
    let in_registry = is_webview2_in_registry();
    let on_disk = is_webview2_on_disk();
    dlog!("WebView2 check: registry={in_registry}, disk={on_disk}");
    in_registry || on_disk
}

pub fn bootstrap_webview2() -> Result<(), String> {
    dlog!("bootstrap_webview2: downloading WebView2 bootstrapper");

    let locked = shell::download_and_verify(config::WEBVIEW2_URL, "exe").map_err(|e| {
        dlog!("bootstrap_webview2: download/verify failed: {e}");
        "Failed to download or verify WebView2.".to_string()
    })?;

    dlog!("bootstrap_webview2: running installer...");
    let path_str = locked.path().to_string_lossy().into_owned();
    let install_result = std::process::Command::new(&path_str)
        .args(["/silent", "/install"])
        .status();

    drop(locked);

    match &install_result {
        Ok(status) if status.success() => dlog!("bootstrap_webview2: install succeeded"),
        Ok(status) => {
            dlog!(
                "bootstrap_webview2: installer exited with code {:?}",
                status.code()
            );
            return Err("WebView2 installer failed.".into());
        }
        Err(e) => {
            dlog!("bootstrap_webview2: installer failed: {e}");
            return Err("WebView2 installer could not be launched.".into());
        }
    }

    if is_webview2_in_registry() {
        dlog!("bootstrap_webview2: verified — registry keys present");
    } else {
        dlog!("bootstrap_webview2: registry keys still missing after install");
    }

    Ok(())
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    dlog!("Tauri builder starting...");
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![install, exit_app, log_js_error])
        .setup(|app| {
            use tauri::Manager;
            dlog!("Tauri setup hook fired");
            if let Some(window) = app.get_webview_window("main") {
                dlog!("Main window found, label={}", window.label());
                match window.url() {
                    Ok(url) => dlog!("Window URL: {}", url),
                    Err(e) => dlog!("Window URL error: {e}"),
                }
            } else {
                dlog!("WARNING: main window not found in setup!");
            }
            Ok(())
        })
        .run(tauri::generate_context!())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_arg_empty_string() {
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn quote_arg_simple_word() {
        assert_eq!(quote_arg("hello"), "hello");
    }

    #[test]
    fn quote_arg_no_special_chars() {
        assert_eq!(quote_arg("C:\\Program\\file.exe"), "C:\\Program\\file.exe");
    }

    #[test]
    fn quote_arg_with_spaces() {
        assert_eq!(quote_arg("hello world"), "\"hello world\"");
    }

    #[test]
    fn quote_arg_with_tab() {
        assert_eq!(quote_arg("hello\tworld"), "\"hello\tworld\"");
    }

    #[test]
    fn quote_arg_with_embedded_quote() {
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn quote_arg_trailing_backslashes() {
        assert_eq!(quote_arg("path\\\\"), "path\\\\");
        assert_eq!(quote_arg("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote_arg("a b\\\\"), "\"a b\\\\\\\\\"");
    }

    #[test]
    fn quote_arg_backslashes_before_embedded_quote() {
        assert_eq!(quote_arg("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn quote_arg_mixed_backslashes_and_spaces() {
        assert_eq!(
            quote_arg("C:\\Program Files\\app"),
            "\"C:\\Program Files\\app\""
        );
    }

    #[test]
    fn quote_arg_only_spaces() {
        assert_eq!(quote_arg("   "), "\"   \"");
    }

    #[test]
    fn quote_arg_only_quotes() {
        assert_eq!(quote_arg("\"\"\""), "\"\\\"\\\"\\\"\"");
    }

    #[test]
    fn quote_arg_adversarial_nested_quotes() {
        let input = "he said \"she said \\\"hello\\\"\"";
        let result = quote_arg(input);
        assert!(result.starts_with('"') && result.ends_with('"'));
    }

    #[test]
    fn quote_arg_all_backslashes() {
        assert_eq!(quote_arg("\\\\\\"), "\\\\\\");
    }

    #[test]
    fn quote_arg_long_string() {
        let long = "a ".repeat(5000);
        let result = quote_arg(&long);
        assert!(result.starts_with('"'));
        assert!(result.ends_with('"'));
        assert!(result.len() > 10000);
    }
}
