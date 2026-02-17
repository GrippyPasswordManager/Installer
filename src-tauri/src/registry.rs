use std::path::Path;

use crate::config;
use crate::log::dlog;

fn install_size_kb() -> u32 {
    const MAX_DEPTH: u32 = 32;

    fn dir_size(path: &Path, depth: u32) -> u64 {
        if depth >= MAX_DEPTH {
            return 0;
        }
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    total += dir_size(&path, depth + 1);
                } else if let Ok(meta) = path.metadata() {
                    total += meta.len();
                }
            }
        }
        total
    }
    (dir_size(Path::new(config::INSTALL_DIR), 0) / 1024) as u32
}

fn today_yyyymmdd() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (secs / 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y}{m:02}{d:02}")
}

pub fn register_uninstaller() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::RegKey;
    use winreg::enums::*;

    let self_exe = std::env::current_exe()?;
    let installer_dest = Path::new(config::INSTALL_DIR).join(config::INSTALLER_BIN);
    dlog!(
        "registry::register_uninstaller: copying {} -> {}",
        self_exe.display(),
        installer_dest.display()
    );
    std::fs::copy(&self_exe, &installer_dest)?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let (key, _) = hklm.create_subkey(config::UNINSTALL_REG_PATH)?;
    dlog!(
        "registry::register_uninstaller: writing to {}",
        config::UNINSTALL_REG_PATH
    );

    let app_icon = Path::new(config::INSTALL_DIR).join(config::APP_BIN);
    let uninstall_string = format!(r#""{}" --uninstall"#, installer_dest.to_string_lossy());
    let quiet_uninstall_string = format!(r#""{}" --uninstall"#, installer_dest.to_string_lossy());
    let size_kb = install_size_kb();
    let date = today_yyyymmdd();

    key.set_value("DisplayName", &config::APP_NAME)?;
    key.set_value("DisplayVersion", &config::APP_VERSION)?;
    key.set_value("Publisher", &config::PUBLISHER)?;
    key.set_value("InstallLocation", &config::INSTALL_DIR)?;
    key.set_value("UninstallString", &uninstall_string)?;
    key.set_value("QuietUninstallString", &quiet_uninstall_string)?;
    key.set_value("DisplayIcon", &app_icon.to_string_lossy().as_ref())?;
    key.set_value("EstimatedSize", &size_kb)?;
    key.set_value("InstallDate", &date)?;
    key.set_value("NoModify", &1u32)?;
    key.set_value("NoRepair", &1u32)?;

    dlog!("registry::register_uninstaller: done (size={size_kb}KB, date={date})");
    Ok(())
}

pub fn remove_uninstaller() {
    use winreg::RegKey;
    use winreg::enums::*;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let _ = hklm.delete_subkey_all(config::UNINSTALL_REG_PATH);
    dlog!("registry::remove_uninstaller: done");
}
