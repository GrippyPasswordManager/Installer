use std::path::Path;

use crate::config;
use crate::log::dlog;

fn install_size_kb() -> u32 {
    fn dir_size(path: &Path, remaining_depth: u32) -> u64 {
        if remaining_depth == 0 {
            return 0;
        }
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    total += dir_size(&path, remaining_depth - 1);
                } else if let Ok(meta) = path.metadata() {
                    total += meta.len();
                }
            }
        }
        total
    }
    (dir_size(config::install_dir(), config::MAX_DIRECTORY_DEPTH) / 1024) as u32
}

fn today_yyyymmdd() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let date = crate::log::civil_date_from_epoch_secs(secs);
    format!("{}{:02}{:02}", date.year, date.month, date.day)
}

pub fn register_uninstaller() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::RegKey;
    use winreg::enums::*;

    let self_exe = std::env::current_exe()?;
    let installer_dest = config::installer_path();
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

    let app_icon = config::app_path();
    let uninstall_string = format!(r#""{}" --uninstall"#, installer_dest.to_string_lossy());
    let size_kb = install_size_kb();
    let date = today_yyyymmdd();

    key.set_value("DisplayName", &config::APP_NAME)?;
    key.set_value("DisplayVersion", &config::APP_VERSION)?;
    key.set_value("Publisher", &config::PUBLISHER)?;
    key.set_value("InstallLocation", &config::INSTALL_DIR)?;
    key.set_value("UninstallString", &uninstall_string)?;
    key.set_value("QuietUninstallString", &uninstall_string)?;
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
