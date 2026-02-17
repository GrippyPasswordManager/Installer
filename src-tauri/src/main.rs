// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    grippy_installer::log::init();
    grippy_installer::log::log("main() started");

    if std::env::args().any(|a| a == "--uninstall") {
        grippy_installer::log::log("--uninstall flag detected");
        if !grippy_installer::is_elevated() {
            grippy_installer::log::log("Not elevated for uninstall, requesting elevation");
            match grippy_installer::self_elevate() {
                Ok(()) => {
                    grippy_installer::log::log("Elevated uninstall instance launched, exiting");
                    return;
                }
                Err(e) => {
                    grippy_installer::log::log(&format!("Elevation for uninstall failed: {e}"));
                    grippy_installer::show_error_msgbox(&format!(
                        "Administrator permissions are required to uninstall Grippy.\n\n{e}"
                    ));
                    return;
                }
            }
        }
        grippy_installer::log::log("Running uninstall as elevated");
        grippy_installer::uninstall();
        return;
    }

    if !grippy_installer::is_elevated() {
        grippy_installer::log::log("Not elevated, requesting elevation before Tauri starts");
        match grippy_installer::self_elevate() {
            Ok(()) => {
                grippy_installer::log::log(
                    "Elevated instance launched, exiting non-elevated instance",
                );
                return;
            }
            Err(e) => {
                grippy_installer::log::log(&format!("Elevation failed: {e}"));
                grippy_installer::show_error_msgbox(&format!(
                    "Administrator permissions are required to install Grippy.\n\n{e}"
                ));
                return;
            }
        }
    }

    grippy_installer::log::log("Running as elevated, proceeding");

    let wv2 = grippy_installer::is_webview2_present();
    grippy_installer::log::log(&format!("WebView2 present: {wv2}"));
    if !wv2 {
        grippy_installer::log::log("WebView2 not found, bootstrapping...");
        if let Err(e) = grippy_installer::bootstrap_webview2() {
            grippy_installer::log::log(&format!("WebView2 bootstrap failed: {e}"));
            grippy_installer::show_error_msgbox(&e);
            return;
        }
        grippy_installer::log::log("WebView2 bootstrap complete");
    }

    grippy_installer::log::log("Launching Tauri...");

    match grippy_installer::run() {
        Ok(()) => {
            grippy_installer::log::log("Tauri exited normally");
        }
        Err(e) => {
            grippy_installer::log::log(&format!("Tauri failed: {e}"));
            grippy_installer::show_error_msgbox(
                "Grippy Installer failed to start.\n\nCheck the log for details.",
            );
        }
    }
}
