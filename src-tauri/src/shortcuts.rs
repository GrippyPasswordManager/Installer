use std::path::Path;

use crate::config;
use crate::log::dlog;

pub fn create() -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize, IPersistFile,
    };
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{HSTRING, Interface, PCWSTR};

    let target = config::app_path();
    let target_str = target.to_string_lossy();
    dlog!("shortcuts::create: target={target_str}");

    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()? };

    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)? };

        let target_h = HSTRING::from(target.as_os_str());
        unsafe { link.SetPath(PCWSTR(target_h.as_ptr()))? };

        let workdir_h = HSTRING::from(config::INSTALL_DIR);
        unsafe { link.SetWorkingDirectory(PCWSTR(workdir_h.as_ptr()))? };

        let persist: IPersistFile = link.cast()?;

        remove_preexisting_symlink(Path::new(config::DESKTOP_LNK));
        let desktop_h = HSTRING::from(config::DESKTOP_LNK);
        unsafe { persist.Save(PCWSTR(desktop_h.as_ptr()), true)? };
        dlog!("shortcuts::create: created {}", config::DESKTOP_LNK);

        remove_preexisting_symlink(Path::new(config::START_MENU_LNK));
        let startmenu_h = HSTRING::from(config::START_MENU_LNK);
        unsafe { persist.Save(PCWSTR(startmenu_h.as_ptr()), true)? };
        dlog!("shortcuts::create: created {}", config::START_MENU_LNK);

        Ok(())
    })();

    unsafe { CoUninitialize() };
    result
}

fn remove_preexisting_symlink(path: &Path) {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            dlog!(
                "shortcuts: removing pre-existing symlink at {}",
                path.display()
            );
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn remove() {
    let _ = std::fs::remove_file(config::DESKTOP_LNK);
    let _ = std::fs::remove_file(config::START_MENU_LNK);
    dlog!("shortcuts::remove: done");
}
