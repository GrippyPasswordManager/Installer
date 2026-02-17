use crate::config;
use crate::log::dlog;
use crate::shell;

fn is_vcredist_installed() -> bool {
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64") {
        Ok(key) => {
            let major: u32 = key.get_value("Major").unwrap_or(0);
            let minor: u32 = key.get_value("Minor").unwrap_or(0);
            dlog!("VCRedist registry: Major={major}, Minor={minor}");
            major >= 14
        }
        Err(e) => {
            dlog!("VCRedist registry key not found: {e}");
            false
        }
    }
}

pub fn ensure_vcredist() -> Result<bool, Box<dyn std::error::Error>> {
    dlog!("ensure_vcredist: checking...");
    if is_vcredist_installed() {
        dlog!("ensure_vcredist: already installed, skipping");
        return Ok(true);
    }

    let installer_path = shell::csprng_temp_path("exe")?;
    dlog!("ensure_vcredist: downloading VC++ Redistributable");
    shell::download_and_verify(config::VCREDIST_URL, &installer_path)?;
    dlog!("ensure_vcredist: download complete, running installer...");

    let path_str = installer_path.to_string_lossy();
    let status = shell::silent(&path_str)
        .args(["/install", "/quiet", "/norestart"])
        .status();

    let _ = std::fs::remove_file(&installer_path);

    let status = status?;
    let code = status.code().unwrap_or(-1);
    dlog!("ensure_vcredist: installer exited with code {code}");
    if !status.success() && code != 1638 && code != 3010 {
        return Err(format!("VC++ installer exited with code {code}").into());
    }
    Ok(false)
}

pub fn ensure_webview2() -> Result<bool, Box<dyn std::error::Error>> {
    dlog!("ensure_webview2: checking...");
    if is_webview2_installed() {
        dlog!("ensure_webview2: already installed, skipping");
        return Ok(true);
    }

    let bootstrapper_path = shell::csprng_temp_path("exe")?;
    dlog!("ensure_webview2: downloading WebView2 bootstrapper");
    shell::download_and_verify(config::WEBVIEW2_URL, &bootstrapper_path)?;
    dlog!("ensure_webview2: download complete, running installer...");

    let path_str = bootstrapper_path.to_string_lossy();
    let status = shell::silent(&path_str)
        .args(["/silent", "/install"])
        .status();

    let _ = std::fs::remove_file(&bootstrapper_path);

    let status = status?;
    let code = status.code().unwrap_or(-1);
    dlog!("ensure_webview2: installer exited with code {code}");
    if !status.success() {
        return Err(format!("WebView2 installer exited with code {code}").into());
    }
    Ok(false)
}

fn is_webview2_installed() -> bool {
    crate::is_webview2_present()
}
