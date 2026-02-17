use std::os::windows::process::CommandExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::config;
use crate::log::dlog;
use crate::shell;

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn is_service_gone() -> bool {
    let output = shell::system32_command("sc.exe")
        .args(["query", config::SERVICE_NAME])
        .output();
    match output {
        Ok(o) => !o.status.success(),
        Err(_) => true,
    }
}

fn is_service_stopped() -> bool {
    let output = shell::system32_command("sc.exe")
        .args(["query", config::SERVICE_NAME])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("STOPPED") || !o.status.success()
        }
        Err(_) => true,
    }
}

fn wait_until(condition: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < TEARDOWN_TIMEOUT {
        if condition() {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    false
}

pub fn teardown_existing() -> Result<(), Box<dyn std::error::Error>> {
    dlog!(
        "service::teardown_existing: stopping {}",
        config::SERVICE_NAME
    );
    shell::system32_run_ignore("sc.exe", &["stop", config::SERVICE_NAME]);
    if !wait_until(is_service_stopped) {
        return Err("Service did not stop within timeout".into());
    }
    dlog!("service::teardown_existing: service stopped, deleting...");
    shell::system32_run_ignore("sc.exe", &["delete", config::SERVICE_NAME]);
    if !wait_until(is_service_gone) {
        return Err("Service was not deleted within timeout".into());
    }
    dlog!("service::teardown_existing: done");
    Ok(())
}

pub fn register_and_start() -> Result<(), Box<dyn std::error::Error>> {
    let bin_path = Path::new(config::INSTALL_DIR)
        .join(config::SERVICE_BIN)
        .to_string_lossy()
        .into_owned();

    dlog!("service::register_and_start: creating service, binPath={bin_path}");

    let mut cmd = shell::system32_command("sc.exe");
    cmd.raw_arg("create");
    cmd.raw_arg(config::SERVICE_NAME);
    cmd.raw_arg(format!("binPath= \"{}\"", bin_path));
    cmd.raw_arg("start= auto");
    cmd.raw_arg(format!("DisplayName= \"{}\"", config::SERVICE_DISPLAY_NAME));

    let create = cmd.output()?;

    let stderr = String::from_utf8_lossy(&create.stderr);
    let stdout = String::from_utf8_lossy(&create.stdout);
    dlog!(
        "service::register_and_start: sc create: status={} stdout={stdout} stderr={stderr}",
        create.status
    );

    if !create.status.success() {
        return Err(format!("sc create failed: {stderr}{stdout}").into());
    }
    dlog!("service::register_and_start: service created");

    let mut desc = shell::system32_command("sc.exe");
    desc.raw_arg("description");
    desc.raw_arg(config::SERVICE_NAME);
    desc.raw_arg(format!("\"{}\"", config::SERVICE_DESCRIPTION));
    if let Ok(o) = desc.output() {
        if !o.status.success() {
            dlog!(
                "service::register_and_start: sc description failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }

    let mut fail = shell::system32_command("sc.exe");
    fail.raw_arg("failure");
    fail.raw_arg(config::SERVICE_NAME);
    fail.raw_arg("reset= 86400");
    fail.raw_arg("actions= restart/5000/restart/10000//");
    if let Ok(o) = fail.output() {
        if !o.status.success() {
            dlog!(
                "service::register_and_start: sc failure config failed: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
    }

    dlog!("service::register_and_start: starting service...");
    let start = shell::system32_command("sc.exe")
        .args(["start", config::SERVICE_NAME])
        .output()?;

    if !start.status.success() {
        let stderr = String::from_utf8_lossy(&start.stderr);
        let stdout = String::from_utf8_lossy(&start.stdout);
        dlog!("service::register_and_start: sc start failed: stderr={stderr} stdout={stdout}");
        return Err(format!("sc start failed: {stderr}{stdout}").into());
    }
    dlog!("service::register_and_start: service started");

    Ok(())
}
