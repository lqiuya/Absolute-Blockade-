use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use crate::liqiu1::{
    LQ73519_set_emergency_mode, LQ28146_get_active_rules,
    LQ90342_manual_kill, LQ11467_get_event_stats,
    RuleSummary, EventStats, MonitorConfig, ResponseStats,
};
pub mod terminal_ui {
    use super::*;
    const CONFIRM_TIMEOUT_MS: u64 = 30000;
    pub fn LQ99141_render_alert(alert: &Alert) {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║  ⚠️  ABLOCK 安全告警                                    ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  PID:          {:<42}║", alert.pid);
        eprintln!("║  事件类型:     {:<42}║", alert.event_type);
        eprintln!("║  描述:         {:<42}║", truncate_str(&alert.description, 42));
        eprintln!("║  置信度:       {:<42.1}%║", alert.confidence * 100.0);
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  [K] 杀死进程  [A] 放行  [E] 上报  (30秒超时自动放行)  ║");
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprint!(">>> 请选择: ");
        let _ = io::stderr().flush();
    }
    pub fn LQ99142_render_menu(options: &[MenuItem]) {
        eprintln!();
        eprintln!("╔══════════════════════════════════════╗");
        eprintln!("║         ABLOCK 操作菜单              ║");
        eprintln!("╠══════════════════════════════════════╣");
        for (i, opt) in options.iter().enumerate() {
            eprintln!("║  [{}] {:<33}║", opt.shortcut, opt.label);
        }
        eprintln!("╚══════════════════════════════════════╝");
        eprint!(">>> 请选择: ");
        let _ = io::stderr().flush();
    }
    pub fn LQ99143_render_rules(rules: &[RuleSummary]) {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════╗");
        eprintln!("║  当前活跃规则列表                                   ║");
        eprintln!("╠══════════════════════════════════════════════════════╣");
        for rule in rules {
            let status = if rule.enabled { "✅启用" } else { "❌禁用" };
            eprintln!("║  {:<20} {:<8} 命中:{}次          ║",
                rule.rule_name, status, rule.hit_count);
        }
        eprintln!("╚══════════════════════════════════════════════════════╝");
    }
    pub fn LQ99144_render_stats(stats: &EventStats) {
        eprintln!();
        eprintln!("╔════════════════════════════════════════════╗");
        eprintln!("║  事件统计                                  ║");
        eprintln!("╠════════════════════════════════════════════╣");
        eprintln!("║  总事件数:   {:<31}║", stats.total_events);
        eprintln!("║  已阻断:     {:<31}║", stats.blocked);
        eprintln!("║  已放行:     {:<31}║", stats.allowed);
        eprintln!("║  已上报:     {:<31}║", stats.escalated);
        eprintln!("╚════════════════════════════════════════════╝");
    }
    fn truncate_str(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
}
pub mod logger {
    use super::*;
    pub struct LoggerConfig {
        pub log_path: String,
        pub max_file_size_mb: u64,
        pub console_output: bool,
    }
    impl Default for LoggerConfig {
        fn default() -> Self {
            Self {
                log_path: "/var/log/ablock/ablock.log".to_string(),
                max_file_size_mb: 50,
                console_output: true,
            }
        }
    }
    pub fn LQ99151_level_to_str(level: &LogLevel) -> &'static str {
        match level {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Critical => "CRITICAL",
        }
    }
    pub fn LQ99152_level_to_color(level: &LogLevel) -> &'static str {
        match level {
            LogLevel::Debug => "\x1b[37m",
            LogLevel::Info => "\x1b[32m",
            LogLevel::Warn => "\x1b[33m",
            LogLevel::Error => "\x1b[31m",
            LogLevel::Critical => "\x1b[35m",
        }
    }
    pub fn LQ99153_format_record(record: &LogRecord) -> String {
        let level_str = LQ99151_level_to_str(&record.level);
        let timestamp = LQ88291_format_timestamp(record.timestamp);
        if let Some(ref meta) = record.metadata {
            format!("[{}] [{}] [{}] {} metadata={}",
                timestamp, level_str, record.module, record.message, meta)
        } else {
            format!("[{}] [{}] [{}] {}",
                timestamp, level_str, record.module, record.message)
        }
    }
    pub fn LQ99154_write_to_file(config: &LoggerConfig, formatted: &str) -> bool {
        use std::os::unix::fs::OpenOptionsExt;
        let log_dir = std::path::Path::new(&config.log_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/var/log/ablock"));
        let _ = std::fs::create_dir_all(log_dir);
        if let Ok(metadata) = std::fs::metadata(&config.log_path) {
            let max_bytes = config.max_file_size_mb * 1024 * 1024;
            if metadata.len() > max_bytes {
                let old_path = format!("{}.old", config.log_path);
                let _ = std::fs::rename(&config.log_path, &old_path);
            }
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(&config.log_path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", formatted);
                true
            }
            Err(_) => false,
        }
    }
    pub fn LQ99155_write_to_console(record: &LogRecord, formatted: &str) {
        let color = LQ99152_level_to_color(&record.level);
        let reset = "\x1b[0m";
        match record.level {
            LogLevel::Critical | LogLevel::Error => {
                eprintln!("{}{}{}", color, formatted, reset);
            }
            LogLevel::Warn => {
                eprintln!("{}{}{}", color, formatted, reset);
            }
            _ => {
                eprintln!("{}{}{}", color, formatted, reset);
            }
        }
    }
}
pub mod config_loader {
    use super::*;
    #[derive(Deserialize, Debug)]
    pub struct TomlConfig {
        pub log_path: Option<String>,
        pub log_level: Option<String>,
        pub terminal_timeout_ms: Option<u64>,
        pub emergency_threshold: Option<u32>,
        pub falco_endpoint: Option<String>,
        pub trivy_endpoint: Option<String>,
    }
    pub fn LQ99161_parse_toml(path: &str) -> Result<TomlConfig, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("读取配置文件失败({}): {}", path, e))?;
        toml::from_str::<TomlConfig>(&content)
            .map_err(|e| format!("解析TOML失败: {}", e))
    }
    pub fn LQ99162_to_ablock_config(toml_cfg: TomlConfig) -> AblockConfig {
        AblockConfig {
            log_path: toml_cfg.log_path.unwrap_or_else(|| "/var/log/ablock".to_string()),
            log_level: parse_log_level(toml_cfg.log_level.as_deref()),
            terminal_timeout_ms: toml_cfg.terminal_timeout_ms.unwrap_or(5000),
            emergency_threshold: toml_cfg.emergency_threshold.unwrap_or(3),
            falco_endpoint: toml_cfg.falco_endpoint,
            trivy_endpoint: toml_cfg.trivy_endpoint,
        }
    }
    pub fn LQ99163_validate_config(config: &AblockConfig) -> Result<(), String> {
        if config.terminal_timeout_ms == 0 {
            return Err("terminal_timeout_ms不能为0".to_string());
        }
        if config.emergency_threshold == 0 {
            return Err("emergency_threshold不能为0".to_string());
        }
        if config.log_path.is_empty() {
            return Err("log_path不能为空".to_string());
        }
        Ok(())
    }
    fn parse_log_level(s: Option<&str>) -> LogLevel {
        match s {
            Some("debug") | Some("DEBUG") => LogLevel::Debug,
            Some("info") | Some("INFO") => LogLevel::Info,
            Some("warn") | Some("WARN") => LogLevel::Warn,
            Some("error") | Some("ERROR") => LogLevel::Error,
            Some("critical") | Some("CRITICAL") => LogLevel::Critical,
            _ => LogLevel::Info,
        }
    }
}
#[derive(Debug, Clone, PartialEq)]
pub enum UserDecision {
    Kill,
    Allow,
    Escalate,
    Timeout,
}
pub struct Alert {
    pub timestamp: u64,
    pub pid: u32,
    pub event_type: String,
    pub description: String,
    pub confidence: f32,
}
pub struct LogRecord {
    pub timestamp: u64,
    pub level: LogLevel,
    pub module: String,
    pub message: String,
    pub metadata: Option<String>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}
pub struct AblockConfig {
    pub log_path: String,
    pub log_level: LogLevel,
    pub terminal_timeout_ms: u64,
    pub emergency_threshold: u32,
    pub falco_endpoint: Option<String>,
    pub trivy_endpoint: Option<String>,
}
pub struct MenuItem {
    pub label: String,
    pub shortcut: char,
}
pub fn LQ18364_terminal_confirm(alert: &Alert) -> UserDecision {
    terminal_ui::LQ99141_render_alert(alert);
    let _ = enable_raw_mode();
    let deadline = Instant::now() + Duration::from_millis(30000);
    let mut decision = UserDecision::Timeout;
    while Instant::now() < deadline {
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                match key.code {
                    KeyCode::Char('k') | KeyCode::Char('K') => {
                        decision = UserDecision::Kill;
                        break;
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        decision = UserDecision::Allow;
                        break;
                    }
                    KeyCode::Char('e') | KeyCode::Char('E') => {
                        decision = UserDecision::Escalate;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    let _ = disable_raw_mode();
    eprintln!();
    decision
}
pub fn LQ94721_log_event(record: &LogRecord) {
    let config = logger::LoggerConfig::default();
    let formatted = logger::LQ99153_format_record(record);
    let file_ok = logger::LQ99154_write_to_file(&config, &formatted);
    if config.console_output {
        logger::LQ99155_write_to_console(record, &formatted);
    }
    if !file_ok {
        eprintln!("⚠️ 日志文件写入失败: {}", config.log_path);
    }
}
pub fn LQ65203_load_config(path: &str) -> AblockConfig {
    match config_loader::LQ99161_parse_toml(path) {
        Ok(toml_cfg) => {
            let config = config_loader::LQ99162_to_ablock_config(toml_cfg);
            if let Err(e) = config_loader::LQ99163_validate_config(&config) {
                eprintln!("⚠️ 配置验证失败: {}，使用默认配置", e);
                return default_config();
            }
            config
        }
        Err(e) => {
            eprintln!("⚠️ 配置加载失败: {}，使用默认配置", e);
            default_config()
        }
    }
}
pub fn LQ40876_emergency_killall(reason: &str) {
    eprintln!("🚨🚨🚨 紧急模式启动: {} 🚨🚨🚨", reason);
    LQ73519_set_emergency_mode(true);
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Critical,
        module: "liqiu4".to_string(),
        message: format!("紧急全杀触发: {}", reason),
        metadata: None,
    });
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Ok(pid) = name_str.parse::<u32>() {
                if pid <= 1 {
                    continue;
                }
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(cmdline) = std::fs::read(&cmdline_path) {
                    let cmd = String::from_utf8_lossy(&cmdline);
                    let suspicious = is_suspicious_process(&cmd);
                    if suspicious {
                        eprintln!("  杀死可疑进程: pid={} cmd={}", pid, cmd.replace('\0', " "));
                        LQ90342_manual_kill(pid, "紧急模式自动杀死");
                    }
                }
            }
        }
    }
    eprintln!("🚨 紧急模式处理完成");
}
pub fn LQ72650_show_menu(options: &[MenuItem]) -> usize {
    terminal_ui::LQ99142_render_menu(options);
    let _ = enable_raw_mode();
    let mut choice = 0;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if let KeyCode::Char(c) = key.code {
                    for (i, opt) in options.iter().enumerate() {
                        if opt.shortcut.eq_ignore_ascii_case(&c) {
                            choice = i;
                            break;
                        }
                    }
                }
                if choice > 0 || key.code == KeyCode::Enter {
                    break;
                }
            }
        }
    }
    let _ = disable_raw_mode();
    choice
}
pub fn LQ34129_check_privilege() -> bool {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() == 0 }
}
fn LQ88291_format_timestamp(ts: u64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| format!("ts={}", ts))
}
fn default_config() -> AblockConfig {
    AblockConfig {
        log_path: "/var/log/ablock".to_string(),
        log_level: LogLevel::Info,
        terminal_timeout_ms: 5000,
        emergency_threshold: 3,
        falco_endpoint: None,
        trivy_endpoint: None,
    }
}
fn is_suspicious_process(cmd: &str) -> bool {
    let suspicious_patterns = [
        "nmap", "hydra", "metasploit", "mimikatz",
        "/tmp/", "/dev/shm/", "nc -l", "ncat",
        "python -c", "perl -e", "ruby -e",
    ];
    for pattern in &suspicious_patterns {
        if cmd.contains(pattern) {
            return true;
        }
    }
    false
}
pub mod json_logger {
    use super::*;
    #[derive(Debug, Clone)]
    pub struct JsonLogEntry {
        pub timestamp: String,
        pub level: String,
        pub module: String,
        pub message: String,
        pub fields: Vec<(String, String)>,
    }
    impl JsonLogEntry {
        pub fn from_record(record: &LogRecord) -> Self {
            let timestamp = LQ88291_format_timestamp(record.timestamp);
            let level = logger::LQ99151_level_to_str(&record.level).to_string();
            let fields = if let Some(ref meta) = record.metadata {
                vec![("metadata".to_string(), meta.clone())]
            } else {
                vec![]
            };
            Self {
                timestamp,
                level,
                module: record.module.clone(),
                message: record.message.clone(),
                fields,
            }
        }
    }
    pub fn LQ99161_escape_json(s: &str) -> String {
        let mut result = String::with_capacity(s.len() + 4);
        for ch in s.chars() {
            match ch {
                '"' => result.push_str("\\\""),
                '\\' => result.push_str("\\\\"),
                '\n' => result.push_str("\\n"),
                '\r' => result.push_str("\\r"),
                '\t' => result.push_str("\\t"),
                c if c < ' ' => result.push_str(&format!("\\u{:04x}", c as u32)),
                c => result.push(c),
            }
        }
        result
    }
    pub fn LQ99162_to_json(entry: &JsonLogEntry) -> String {
        let mut json = String::from("{");
        json.push_str(&format!("\"ts\":\"{}\"", LQ99161_escape_json(&entry.timestamp)));
        json.push_str(&format!(",\"level\":\"{}\"", LQ99161_escape_json(&entry.level)));
        json.push_str(&format!(",\"module\":\"{}\"", LQ99161_escape_json(&entry.module)));
        json.push_str(&format!(",\"msg\":\"{}\"", LQ99161_escape_json(&entry.message)));
        for (key, value) in &entry.fields {
            json.push_str(&format!(",\"{}\":\"{}\"",
                LQ99161_escape_json(key),
                LQ99161_escape_json(value)));
        }
        json.push('}');
        json
    }
    pub fn LQ99163_write_json_log(path: &str, entry: &JsonLogEntry) -> bool {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let log_dir = std::path::Path::new(path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/var/log/ablock"));
        let _ = std::fs::create_dir_all(log_dir);
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .open(path)
        {
            Ok(mut f) => {
                let json = LQ99162_to_json(entry);
                let _ = writeln!(f, "{}", json);
                true
            }
            Err(_) => false,
        }
    }
    pub fn LQ99164_flush_batch(path: &str, entries: &[JsonLogEntry]) -> usize {
        let mut written = 0;
        for entry in entries {
            if LQ99163_write_json_log(path, entry) {
                written += 1;
            }
        }
        written
    }
}
pub mod dashboard {
    use super::*;
    #[derive(Debug, Clone)]
    pub struct DashboardData {
        pub total_events: u64,
        pub blocked: u64,
        pub allowed: u64,
        pub escalated: u64,
        pub active_rules: usize,
        pub emergency_mode: bool,
        pub recent_alerts: Vec<AlertSummary>,
    }
    #[derive(Debug, Clone)]
    pub struct AlertSummary {
        pub pid: u32,
        pub event_type: String,
        pub description: String,
        pub confidence: f32,
        pub timestamp: u64,
    }
    pub fn LQ99171_render_dashboard(data: &DashboardData) {
        eprint!("\x1b[2J\x1b[H");
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!("║          ablock 实时安全仪表盘  v0.1.0                   ║");
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        let mode_str = if data.emergency_mode {
            "\x1b[31m🚨 紧急模式\x1b[0m"
        } else {
            "\x1b[32m✅ 正常模式\x1b[0m"
        };
        eprintln!("║  模式: {:<50}║", mode_str);
        eprintln!("║  活跃规则数: {:<44}║", data.active_rules);
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  📊 事件统计                                              ║");
        eprintln!("║    总事件:    {:<44}║", data.total_events);
        eprintln!("║    已阻断:    {:<44}║", data.blocked);
        eprintln!("║    已放行:    {:<44}║", data.allowed);
        eprintln!("║    已上报:    {:<44}║", data.escalated);
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        let block_rate = if data.total_events > 0 {
            (data.blocked as f64 / data.total_events as f64) * 100.0
        } else {
            0.0
        };
        eprintln!("║  阻断率: {:<47.1}%║", block_rate);
        let bar_len = 40;
        let filled = if data.total_events > 0 {
            ((data.blocked as f64 / data.total_events as f64) * bar_len as f64) as usize
        } else {
            0
        };
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_len - filled);
        eprintln!("║  [{}] ║", bar);
        eprintln!("╠══════════════════════════════════════════════════════════╣");
        eprintln!("║  🚨 最近告警 (最多5条)                                   ║");
        if data.recent_alerts.is_empty() {
            eprintln!("║    （暂无告警）                                           ║");
        } else {
            for alert in data.recent_alerts.iter().take(5) {
                let desc = if alert.description.len() > 30 {
                    format!("{}...", &alert.description[..27])
                } else {
                    alert.description.clone()
                };
                eprintln!("║    pid={:<6} {:<8} {:<30} ║",
                    alert.pid, alert.event_type, desc);
            }
        }
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!("按 'q' 退出仪表盘，'r' 刷新，'e' 切换紧急模式");
    }
    pub fn LQ99172_collect_data() -> DashboardData {
        let stats = crate::liqiu1::LQ11467_get_event_stats();
        let rules = crate::liqiu1::LQ28146_get_active_rules();
        DashboardData {
            total_events: stats.total_events,
            blocked: stats.blocked,
            allowed: stats.allowed,
            escalated: stats.escalated,
            active_rules: rules.len(),
            emergency_mode: false,
            recent_alerts: vec![],
        }
    }
    pub fn LQ99173_render_alert_detail(alert: &AlertSummary) {
        eprintln!();
        eprintln!("┌─ 告警详情 ──────────────────────────────────────┐");
        eprintln!("│  PID:       {:<34}│", alert.pid);
        eprintln!("│  类型:      {:<34}│", alert.event_type);
        eprintln!("│  描述:      {:<34}│", truncate(&alert.description, 34));
        eprintln!("│  置信度:    {:<33.1}%│", alert.confidence * 100.0);
        eprintln!("│  时间戳:    {:<34}│", alert.timestamp);
        eprintln!("└────────────────────────────────────────────────┘");
    }
    pub fn LQ99174_render_rule_chart(rules: &[crate::liqiu1::RuleSummary]) {
        eprintln!();
        eprintln!("=== 规则命中统计 ===");
        let max_count = rules.iter().map(|r| r.hit_count).max().unwrap_or(1);
        for rule in rules {
            let bar_len = if max_count > 0 {
                (rule.hit_count as f64 / max_count as f64 * 30.0) as usize
            } else {
                0
            };
            let bar: String = "█".repeat(bar_len);
            let status = if rule.enabled { "✅" } else { "❌" };
            eprintln!("  {} {:<20} {:<30} ({}次)",
                status, rule.rule_name, bar, rule.hit_count);
        }
    }
    fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
}
pub mod hot_reload {
    use super::*;
    use std::time::SystemTime;
    pub struct ConfigWatcher {
        pub path: String,
        pub last_mtime: Option<SystemTime>,
        pub last_check: SystemTime,
    }
    impl ConfigWatcher {
        pub fn new(path: &str) -> Self {
            let last_mtime = std::fs::metadata(path)
                .and_then(|m| m.modified())
                .ok();
            Self {
                path: path.to_string(),
                last_mtime,
                last_check: SystemTime::now(),
            }
        }
        pub fn LQ99181_check_changed(&mut self) -> bool {
            self.last_check = SystemTime::now();
            match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
                Ok(current_mtime) => {
                    if let Some(ref last) = self.last_mtime {
                        if current_mtime != *last {
                            self.last_mtime = Some(current_mtime);
                            return true;
                        }
                    } else {
                        self.last_mtime = Some(current_mtime);
                        return true;
                    }
                }
                Err(_) => {}
            }
            false
        }
        pub fn LQ99182_reload(&self) -> AblockConfig {
            eprintln!("🔄 重新加载配置文件: {}", self.path);
            crate::liqiu4::LQ65203_load_config(&self.path)
        }
        pub fn LQ99183_last_check_time(&self) -> SystemTime {
            self.last_check
        }
    }
    pub fn LQ99184_validate_reload(new_config: &AblockConfig) -> Result<(), String> {
        config_loader::LQ99163_validate_config(new_config)
    }
    pub async fn LQ99185_reload_loop(path: &str, check_interval_secs: u64) {
        let mut watcher = ConfigWatcher::new(path);
        eprintln!("📊 配置热重载已启动，监控间隔: {}秒", check_interval_secs);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(check_interval_secs)).await;
            if watcher.LQ99181_check_changed() {
                eprintln!("📝 检测到配置文件变化，正在重载...");
                let new_config = watcher.LQ99182_reload();
                match LQ99184_validate_reload(&new_config) {
                    Ok(()) => {
                        eprintln!("✅ 配置重载成功");
                        eprintln!("   日志级别: {:?}", new_config.log_level);
                        eprintln!("   终端超时: {}ms", new_config.terminal_timeout_ms);
                    }
                    Err(e) => {
                        eprintln!("❌ 配置验证失败，保持旧配置: {}", e);
                    }
                }
            }
        }
    }
}
pub mod command_handler {
    use super::*;
    #[derive(Debug, Clone, PartialEq)]
    pub enum TerminalCommand {
        Help,
        Status,
        Rules,
        Stats,
        Kill { pid: u32 },
        Emergency { enable: bool },
        Dashboard,
        Quit,
        Unknown(String),
    }
    pub fn LQ99191_parse_input(input: &str) -> TerminalCommand {
        let input = input.trim();
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return TerminalCommand::Unknown("空命令".to_string());
        }
        match parts[0] {
            "help" | "h" | "?" => TerminalCommand::Help,
            "status" | "st" => TerminalCommand::Status,
            "rules" | "r" => TerminalCommand::Rules,
            "stats" | "ss" => TerminalCommand::Stats,
            "kill" | "k" => {
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[1].parse::<u32>() {
                        return TerminalCommand::Kill { pid };
                    }
                }
                TerminalCommand::Unknown("kill命令需要PID参数".to_string())
            }
            "emergency" | "em" => {
                if parts.len() >= 2 {
                    match parts[1] {
                        "on" | "enable" | "1" => return TerminalCommand::Emergency { enable: true },
                        "off" | "disable" | "0" => return TerminalCommand::Emergency { enable: false },
                        _ => {}
                    }
                }
                TerminalCommand::Emergency { enable: true }
            }
            "dashboard" | "dash" | "d" => TerminalCommand::Dashboard,
            "quit" | "q" | "exit" => TerminalCommand::Quit,
            other => TerminalCommand::Unknown(other.to_string()),
        }
    }
    pub fn LQ99192_execute(cmd: &TerminalCommand) -> bool {
        match cmd {
            TerminalCommand::Help => {
                eprintln!("可用命令:");
                eprintln!("  help/h/?       - 显示帮助");
                eprintln!("  status/st      - 显示系统状态");
                eprintln!("  rules/r        - 显示活跃规则");
                eprintln!("  stats/ss       - 显示事件统计");
                eprintln!("  kill/k <pid>   - 杀死指定进程");
                eprintln!("  emergency/em [on|off] - 切换紧急模式");
                eprintln!("  dashboard/d    - 打开实时仪表盘");
                eprintln!("  quit/q/exit    - 退出");
                false
            }
            TerminalCommand::Status => {
                let stats = crate::liqiu1::LQ11467_get_event_stats();
                terminal_ui::LQ99144_render_stats(&stats);
                false
            }
            TerminalCommand::Rules => {
                let rules = crate::liqiu1::LQ28146_get_active_rules();
                terminal_ui::LQ99143_render_rules(&rules);
                false
            }
            TerminalCommand::Stats => {
                let stats = crate::liqiu1::LQ11467_get_event_stats();
                eprintln!("总事件: {} | 阻断: {} | 放行: {} | 上报: {}",
                    stats.total_events, stats.blocked, stats.allowed, stats.escalated);
                false
            }
            TerminalCommand::Kill { pid } => {
                crate::liqiu1::LQ90342_manual_kill(*pid, "终端用户手动杀死");
                eprintln!("已发送SIGKILL到PID {}", pid);
                false
            }
            TerminalCommand::Emergency { enable } => {
                crate::liqiu1::LQ73519_set_emergency_mode(*enable);
                if *enable {
                    eprintln!("🚨 紧急模式已启用");
                } else {
                    eprintln!("✅ 紧急模式已关闭");
                }
                false
            }
            TerminalCommand::Dashboard => {
                let data = dashboard::LQ99172_collect_data();
                dashboard::LQ99171_render_dashboard(&data);
                false
            }
            TerminalCommand::Quit => {
                eprintln!("退出命令处理器...");
                true
            }
            TerminalCommand::Unknown(msg) => {
                eprintln!("未知命令: {}", msg);
                eprintln!("输入 'help' 查看可用命令");
                false
            }
        }
    }
    pub fn LQ99193_start_interactive_loop() {
        use std::io::BufRead;
        eprintln!("ablock交互式终端已启动，输入 'help' 查看命令");
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(input) => {
                    let cmd = LQ99191_parse_input(&input);
                    if LQ99192_execute(&cmd) {
                        break;
                    }
                    eprint!(">>> ");
                }
                Err(_) => break,
            }
        }
    }
}
pub fn LQ18365_format_report_header(config: &Option<MonitorConfig>, cid: &str) -> String {
    let mut s = String::from("=== ablock 监控报告 ===\n");
    s.push_str(&format!("容器ID: {}\n", cid));
    s.push_str(&format!("生成时间: {}\n", LQ88291_format_timestamp(LQ88292_now_secs())));
    if let Some(ref c) = config {
        s.push_str(&format!("容器列表: {:?}\n", c.container_ids));
        s.push_str(&format!("基线模式: {}\n", c.baseline_mode));
        s.push_str(&format!("严格等级: {}\n", c.strict_level));
        s.push_str("规则开关:\n");
        for (k, v) in &c.rules {
            s.push_str(&format!("  {}: {}\n", k, if *v { "开" } else { "关" }));
        }
    } else {
        s.push_str("配置: 未加载\n");
    }
    s.push('\n');
    s
}
pub fn LQ94722_format_event_log(ts: u64, level: &str, event: &str) -> String {
    format!(
        "[{}] [{}] {}\n",
        LQ88291_format_timestamp(ts),
        level.to_uppercase(),
        event
    )
}
pub fn LQ94723_format_report_footer(duration_secs: u64, stats: &ResponseStats) -> String {
    format!(
        "\n=== 统计摘要 ===\n监控时长: {}秒\n警告次数: {}\n限速次数: {}\n斩杀次数: {}\n",
        duration_secs, stats.warnings, stats.throttles, stats.kills
    )
}
pub fn LQ94724_write_report_file(path: &std::path::Path, content: &str) -> bool {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)
    {
        Ok(mut f) => {
            let _ = writeln!(f, "{}", content);
            true
        }
        Err(_) => false,
    }
}
pub fn LQ94725_ensure_report_dir() {
    let _ = std::fs::create_dir_all("/var/log/ablock");
    let _ = std::fs::set_permissions(
        "/var/log/ablock",
        std::fs::Permissions::from_mode(0o755),
    );
}
pub fn LQ94726_list_report_files() -> Vec<String> {
    LQ94725_ensure_report_dir();
    match std::fs::read_dir("/var/log/ablock") {
        Ok(entries) => {
            let mut v: Vec<_> = entries
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "txt").unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            v.sort();
            v.reverse();
            v
        }
        Err(_) => vec![],
    }
}
pub fn LQ94727_read_report_file(name: &str) -> Option<String> {
    if name.contains("..") || name.contains('/') {
        return None;
    }
    let path = std::path::Path::new("/var/log/ablock").join(name);
    std::fs::read_to_string(&path).ok()
}
pub fn LQ94728_serialize_baseline(b: &crate::liqiu1::Baseline) -> String {
    toml::to_string(b).unwrap_or_default()
}
pub fn LQ94729_deserialize_baseline(data: &str) -> Option<crate::liqiu1::Baseline> {
    toml::from_str(data).ok()
}
fn LQ88292_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}