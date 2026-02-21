use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config;

static LOG: std::sync::OnceLock<Mutex<PathBuf>> = std::sync::OnceLock::new();

pub(crate) struct CivilDate {
    pub year: i64,
    pub month: u64,
    pub day: u64,
}

pub(crate) fn civil_date_from_epoch_secs(epoch_secs: u64) -> CivilDate {
    let days = (epoch_secs / 86400) as i64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let day_of_era = (z - era * 146097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let year = (year_of_era as i64) + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_offset = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_offset + 2) / 5 + 1;
    let month = if month_offset < 10 {
        month_offset + 3
    } else {
        month_offset - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    CivilDate { year, month, day }
}

fn restrict_dir_acl(dir: &Path) -> bool {
    let dir_str = dir.to_string_lossy();
    matches!(crate::shell::system32_command("icacls.exe")
        .args([
            &*dir_str,
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:(OI)(CI)F",
            "/grant:r",
            "Administrators:(OI)(CI)F",
        ])
        .output(), Ok(output) if output.status.success())
}

fn log_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("Grippy").join("logs");
        if std::fs::create_dir_all(&dir).is_ok() && restrict_dir_acl(&dir) {
            return dir;
        }
    }
    if let Ok(pdata) = std::env::var("PROGRAMDATA") {
        let dir = PathBuf::from(pdata).join("Grippy").join("logs");
        if std::fs::create_dir_all(&dir).is_ok() && restrict_dir_acl(&dir) {
            return dir;
        }
    }
    let dir = std::env::temp_dir().join("Grippy").join("logs");
    if std::fs::create_dir_all(&dir).is_ok() && restrict_dir_acl(&dir) {
        return dir;
    }
    std::env::temp_dir()
}

pub fn sanitize(msg: &str) -> String {
    msg.chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .take(config::SANITIZE_MAX_LENGTH)
        .collect()
}

fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn timestamp() -> String {
    let secs = epoch_secs();
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let date = civil_date_from_epoch_secs(secs);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        date.year, date.month, date.day, hours, minutes, seconds
    )
}

fn parse_line_epoch(line: &str) -> Option<u64> {
    let line = line.strip_prefix('[')?;
    if line.len() < 19 || !line.is_char_boundary(19) {
        return None;
    }
    let year: i64 = line.get(0..4)?.parse().ok()?;
    if line.as_bytes().get(4) != Some(&b'-') {
        return None;
    }
    let month: u64 = line.get(5..7)?.parse().ok()?;
    if line.as_bytes().get(7) != Some(&b'-') {
        return None;
    }
    let day: u64 = line.get(8..10)?.parse().ok()?;
    if line.as_bytes().get(10) != Some(&b' ') {
        return None;
    }
    let h: u64 = line.get(11..13)?.parse().ok()?;
    if line.as_bytes().get(13) != Some(&b':') {
        return None;
    }
    let m: u64 = line.get(14..16)?.parse().ok()?;
    if line.as_bytes().get(16) != Some(&b':') {
        return None;
    }
    let s: u64 = line.get(17..19)?.parse().ok()?;

    let y = if month <= 2 { year - 1 } else { year };
    let mo = if month <= 2 { month + 9 } else { month - 3 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let doy = (153 * mo + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;

    Some(days as u64 * 86400 + h * 3600 + m * 60 + s)
}

pub fn init() {
    let path = log_dir().join("install.log");

    if let Ok(mut file) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&path)
    {
        let cutoff = epoch_secs().saturating_sub(config::MAX_LOG_AGE_SECS);
        let mut content = String::new();
        let _ = file.read_to_string(&mut content);

        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.set_len(0);

        for line in content.lines() {
            if let Some(epoch) = parse_line_epoch(line)
                && epoch >= cutoff
            {
                let _ = writeln!(file, "{line}");
            }
        }

        let _ = writeln!(
            file,
            "[{}] || Session start (PID: {}) ||",
            timestamp(),
            std::process::id()
        );
    }

    let _ = LOG.set(Mutex::new(path));
}

pub fn log(msg: &str) {
    if let Some(path) = LOG.get()
        && let Ok(path) = path.lock()
        && let Ok(mut f) = OpenOptions::new().append(true).open(&*path)
        && f.metadata()
            .map_or(true, |m| m.len() < config::MAX_LOG_BYTES)
    {
        let _ = writeln!(f, "[{}] {msg}", timestamp());
    }
}

pub fn log_fmt(args: std::fmt::Arguments<'_>) {
    let mut buf = String::new();
    let _ = buf.write_fmt(args);
    log(&buf);
}

macro_rules! dlog {
    ($($arg:tt)*) => {
        $crate::log::log_fmt(format_args!($($arg)*))
    };
}
pub(crate) use dlog;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_unix_epoch() {
        let d = civil_date_from_epoch_secs(0);
        assert_eq!((d.year, d.month, d.day), (1970, 1, 1));
    }

    #[test]
    fn civil_date_y2k() {
        let d = civil_date_from_epoch_secs(946684800);
        assert_eq!((d.year, d.month, d.day), (2000, 1, 1));
    }

    #[test]
    fn civil_date_leap_day_2000() {
        let d = civil_date_from_epoch_secs(951782400);
        assert_eq!((d.year, d.month, d.day), (2000, 2, 29));
    }

    #[test]
    fn civil_date_leap_day_2024() {
        let d = civil_date_from_epoch_secs(1709164800);
        assert_eq!((d.year, d.month, d.day), (2024, 2, 29));
    }

    #[test]
    fn civil_date_non_leap_2100_mar_1() {
        let d = civil_date_from_epoch_secs(4107542400);
        assert_eq!((d.year, d.month, d.day), (2100, 3, 1));
    }

    #[test]
    fn civil_date_end_of_year() {
        let d = civil_date_from_epoch_secs(1703980800);
        assert_eq!((d.year, d.month, d.day), (2023, 12, 31));
    }

    #[test]
    fn civil_date_recent() {
        let d = civil_date_from_epoch_secs(1736942400);
        assert_eq!((d.year, d.month, d.day), (2025, 1, 15));
    }

    #[test]
    fn parse_line_epoch_roundtrip() {
        let epoch: u64 = 1700000000;
        let time_of_day = epoch % 86400;
        let h = time_of_day / 3600;
        let m = (time_of_day % 3600) / 60;
        let s = time_of_day % 60;
        let d = civil_date_from_epoch_secs(epoch);
        let line = format!(
            "[{:04}-{:02}-{:02} {:02}:{:02}:{:02}] some log message",
            d.year, d.month, d.day, h, m, s
        );
        assert_eq!(parse_line_epoch(&line), Some(epoch));
    }

    #[test]
    fn parse_line_epoch_midnight() {
        let line = "[2024-06-15 00:00:00] midnight";
        let result = parse_line_epoch(line).unwrap();

        let d = civil_date_from_epoch_secs(result);
        assert_eq!((d.year, d.month, d.day), (2024, 6, 15));
        assert_eq!(result % 86400, 0);
    }

    #[test]
    fn parse_line_epoch_end_of_day() {
        let line = "[2024-06-15 23:59:59] end of day";
        let result = parse_line_epoch(line).unwrap();
        let d = civil_date_from_epoch_secs(result);
        assert_eq!((d.year, d.month, d.day), (2024, 6, 15));
        assert_eq!(result % 86400, 23 * 3600 + 59 * 60 + 59);
    }

    #[test]
    fn parse_line_epoch_missing_bracket() {
        assert_eq!(parse_line_epoch("2024-06-15 12:00:00] msg"), None);
    }

    #[test]
    fn parse_line_epoch_too_short() {
        assert_eq!(parse_line_epoch("[2024-06-15 12:00"), None);
    }

    #[test]
    fn parse_line_epoch_bad_separator() {
        assert_eq!(parse_line_epoch("[2024/06/15 12:00:00] msg"), None);
    }

    #[test]
    fn parse_line_epoch_non_numeric() {
        assert_eq!(parse_line_epoch("[abcd-ef-gh ij:kl:mn] msg"), None);
    }

    #[test]
    fn parse_line_epoch_empty() {
        assert_eq!(parse_line_epoch(""), None);
    }

    #[test]
    fn sanitize_normal_ascii() {
        assert_eq!(sanitize("hello world 123!"), "hello world 123!");
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize("he\0ll\no\tworld\x07"), "helloworld");
    }

    #[test]
    fn sanitize_strips_bidi_overrides() {
        let input = "abc\u{202A}def\u{202E}ghi\u{2066}jkl\u{2069}mno";
        assert_eq!(sanitize(input), "abcdefghijklmno");
    }

    #[test]
    fn sanitize_truncates_at_max_length() {
        let long = "a".repeat(config::SANITIZE_MAX_LENGTH + 100);
        let result = sanitize(&long);
        assert_eq!(result.len(), config::SANITIZE_MAX_LENGTH);
    }

    #[test]
    fn sanitize_preserves_emoji() {
        assert_eq!(sanitize("hello 🎉🔒"), "hello 🎉🔒");
    }

    #[test]
    fn sanitize_preserves_cjk() {
        assert_eq!(sanitize("日本語テスト"), "日本語テスト");
    }

    #[test]
    fn sanitize_empty_string() {
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn sanitize_all_control_chars() {
        let input: String = (0u8..32).map(|b| b as char).collect();
        assert_eq!(sanitize(&input), "");
    }

    #[test]
    fn sanitize_bidi_attack_pattern() {
        let input = "admin\u{202E}txt.exe";
        assert_eq!(sanitize(input), "admintxt.exe");
    }
}
