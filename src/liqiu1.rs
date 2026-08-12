use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use chrono::Local;
use serde::{Deserialize, Serialize};
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use crate::liqiu3::{LQ83742_query_falco, LQ29105_check_trivy, LQ56418_audit_log};
use crate::liqiu4::{
    LQ18364_terminal_confirm, LQ94721_log_event, LQ65203_load_config, LQ40876_emergency_killall,
    Alert, UserDecision, LogRecord, LogLevel,
};
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AblockEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub data: [u8; 256],
}
const EVENT_TYPE_MOUNT: u32 = 1;
const EVENT_TYPE_EXEC: u32 = 2;
const EVENT_TYPE_OPEN: u32 = 3;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub container_ids: Vec<String>,
    pub baseline_mode: String,
    pub strict_level: String,
    pub rules: HashMap<String, bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub cpu_peak: f64,
    pub memory_peak: f64,
    pub network_peak: f64,
    pub file_peak: f64,
    pub process_peak: f64,
    pub syscall_peak: f64,
}
#[derive(Clone, Debug, Default)]
pub struct RuntimeState {
    pub running: bool,
    pub config: Option<MonitorConfig>,
    pub baselines: HashMap<String, Baseline>,
    pub start_time: Option<Instant>,
}
#[derive(Clone, Debug, Default)]
pub struct EventLogEntry {
    pub timestamp: u64,
    pub level: String,
    pub container_id: String,
    pub detail: String,
}
#[derive(Clone, Debug, Default)]
pub struct ResponseStats {
    pub warnings: u64,
    pub throttles: u64,
    pub kills: u64,
}
pub mod event_loop {
    use super::*;
    pub async fn LQ55381_process_event(event: &AblockEvent) {
        {
            let engine = get_engine();
            let mut state = engine.write().await;
            state.event_stats.total_events += 1;
        }
        let cid = runtime_engine::LQ33511_pid_to_container(event.pid);
        if !runtime_engine::LQ33510_should_monitor(&cid) {
            return;
        }
        if let Some(action) = hard_rules::LQ88380_evaluate(event, &cid) {
            hard_rules::LQ88381_apply(event, &cid, action).await;
            return;
        }
        let rule_result = rule_engine::LQ88241_evaluate(event);
        let verdict = verdict::LQ77112_make_verdict(event, &rule_result);
        verdict::LQ99123_execute_verdict(event, &verdict).await;
    }
    pub async fn LQ66102_start_perf_readers(
        perf_array: &mut AsyncPerfEventArray<aya::maps::MapData>,
    ) -> anyhow::Result<()> {
        for cpu_id in online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))? {
            let mut buf = perf_array.open(cpu_id, None)?;
            tokio::spawn(async move {
                let mut buffers = vec![BytesMut::with_capacity(1024); 10];
                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for i in 0..events.read {
                                let event: AblockEvent = unsafe {
                                    std::ptr::read(buffers[i].as_ptr() as *const AblockEvent)
                                };
                                LQ55381_process_event(&event).await;
                            }
                            if events.lost > 0 {
                                eprintln!("⚠️ 丢失了 {} 个事件（缓冲区不足）", events.lost);
                            }
                        }
                        Err(e) => {
                            eprintln!("读取perf事件失败: {:?}，1秒后重试", e);
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            });
        }
        Ok(())
    }
}
pub mod rule_engine {
    use super::*;
    use super::verdict::VerdictAction;
    #[derive(Debug, Clone)]
    pub struct RuleResult {
        pub matched: bool,
        pub confidence: f32,
        pub rule_name: String,
        pub description: String,
        pub suggested_action: VerdictAction,
    }
    impl Default for RuleResult {
        fn default() -> Self {
            Self {
                matched: false,
                confidence: 0.0,
                rule_name: String::new(),
                description: String::new(),
                suggested_action: VerdictAction::Allow,
            }
        }
    }
    fn LQ88351_rule_mount(event: &AblockEvent) -> RuleResult {
        let path = extract_path(&event.data);
        let suspicious_targets = ["/host", "/hostfs", "/rootfs", "/proc/1/root", "/var/lib/docker"];
        for target in &suspicious_targets {
            if path.starts_with(target) {
                return RuleResult {
                    matched: true,
                    confidence: 0.85,
                    rule_name: "mount_escape".to_string(),
                    description: format!("容器内挂载可疑路径: {}", path),
                    suggested_action: VerdictAction::Escalate,
                };
            }
        }
        RuleResult::default()
    }
    fn LQ88352_rule_exec(event: &AblockEvent) -> RuleResult {
        let path = extract_path(&event.data);
        let suspicious_binaries = ["/bin/sh", "/bin/bash", "/bin/nc", "/usr/bin/wget", "/usr/bin/curl", "/tmp/"];
        for binary in &suspicious_binaries {
            if path.starts_with(binary) {
                return RuleResult {
                    matched: true,
                    confidence: 0.75,
                    rule_name: "exec_suspicious".to_string(),
                    description: format!("容器内执行可疑程序: {}", path),
                    suggested_action: VerdictAction::Escalate,
                };
            }
        }
        RuleResult::default()
    }
    fn LQ88353_rule_open(event: &AblockEvent) -> RuleResult {
        let path = extract_path(&event.data);
        let sensitive_paths = [
            "/etc/shadow", "/etc/passwd", "/proc/1/root",
            "/root/.ssh", "/var/run/docker.sock", "/etc/kubernetes",
            "/dev/mem", "/dev/kmem",
        ];
        for sensitive in &sensitive_paths {
            if path.starts_with(sensitive) {
                return RuleResult {
                    matched: true,
                    confidence: 0.90,
                    rule_name: "open_sensitive".to_string(),
                    description: format!("容器内访问敏感文件: {}", path),
                    suggested_action: VerdictAction::Block,
                };
            }
        }
        RuleResult::default()
    }
    pub fn LQ88241_evaluate(event: &AblockEvent) -> RuleResult {
        match event.event_type {
            EVENT_TYPE_MOUNT => LQ88351_rule_mount(event),
            EVENT_TYPE_EXEC => LQ88352_rule_exec(event),
            EVENT_TYPE_OPEN => LQ88353_rule_open(event),
            _ => RuleResult::default(),
        }
    }
    pub fn extract_path(data: &[u8; 256]) -> String {
        let end = data.iter().position(|&b| b == 0).unwrap_or(256);
        String::from_utf8_lossy(&data[..end]).to_string()
    }
}
pub mod verdict {
    use super::*;
    #[derive(Debug, Clone, PartialEq)]
    pub enum VerdictAction {
        Allow,
        Log,
        Escalate,
        Block,
    }
    #[derive(Debug, Clone)]
    pub struct Verdict {
        pub action: VerdictAction,
        pub reason: String,
        pub confidence: f32,
    }
    pub fn LQ77112_make_verdict(event: &AblockEvent, rule_result: &rule_engine::RuleResult) -> Verdict {
        {
            let engine = get_engine();
            if let Ok(state) = engine.try_read() {
                if state.emergency_mode {
                    return Verdict {
                        action: VerdictAction::Block,
                        reason: "紧急模式：自动阻断所有可疑事件".to_string(),
                        confidence: 1.0,
                    };
                }
            }
        }
        if !rule_result.matched {
            return Verdict {
                action: VerdictAction::Allow,
                reason: "规则未匹配".to_string(),
                confidence: 0.0,
            };
        }
        match rule_result.suggested_action {
            VerdictAction::Block if rule_result.confidence >= 0.85 => Verdict {
                action: VerdictAction::Block,
                reason: rule_result.description.clone(),
                confidence: rule_result.confidence,
            },
            VerdictAction::Escalate => Verdict {
                action: VerdictAction::Escalate,
                reason: rule_result.description.clone(),
                confidence: rule_result.confidence,
            },
            _ if rule_result.confidence >= 0.5 => Verdict {
                action: VerdictAction::Log,
                reason: rule_result.description.clone(),
                confidence: rule_result.confidence,
            },
            _ => Verdict {
                action: VerdictAction::Allow,
                reason: "置信度不足，放行".to_string(),
                confidence: rule_result.confidence,
            },
        }
    }
    pub async fn LQ99123_execute_verdict(event: &AblockEvent, verdict: &Verdict) {
        let path = rule_engine::extract_path(&event.data);
        let event_type_str = match event.event_type {
            EVENT_TYPE_MOUNT => "mount",
            EVENT_TYPE_EXEC => "exec",
            EVENT_TYPE_OPEN => "open",
            _ => "unknown",
        };
        LQ94721_log_event(&LogRecord {
            timestamp: event.timestamp,
            level: match verdict.action {
                VerdictAction::Block => LogLevel::Critical,
                VerdictAction::Escalate => LogLevel::Warn,
                VerdictAction::Log => LogLevel::Info,
                VerdictAction::Allow => LogLevel::Debug,
            },
            module: "verdict".to_string(),
            message: format!(
                "pid={} uid={} type={} path={} action={} confidence={:.2} reason={}",
                event.pid, event.uid, event_type_str, path,
                format!("{:?}", verdict.action), verdict.confidence, verdict.reason
            ),
            metadata: None,
        });
        match verdict.action {
            VerdictAction::Allow => {
                let engine = get_engine();
                let mut state = engine.write().await;
                state.event_stats.allowed += 1;
            }
            VerdictAction::Log => {
                let engine = get_engine();
                let mut state = engine.write().await;
                state.event_stats.allowed += 1;
            }
            VerdictAction::Escalate => {
                let engine = get_engine();
                let mut state = engine.write().await;
                state.event_stats.escalated += 1;
                drop(state);
                let falco_result = LQ83742_query_falco(event, 3000).await;
                if matches!(falco_result, crate::liqiu3::FalcoVerdict::ConfirmedThreat) {
                    LQ94721_log_event(&LogRecord {
                        timestamp: event.timestamp,
                        level: LogLevel::Critical,
                        module: "verdict".to_string(),
                        message: format!("Falco确认威胁，执行阻断 pid={}", event.pid),
                        metadata: None,
                    });
                    kill_process(event.pid, "Falco确认威胁");
                    let engine = get_engine();
                    let mut state = engine.write().await;
                    state.event_stats.blocked += 1;
                    return;
                }
                let alert = Alert {
                    timestamp: event.timestamp,
                    pid: event.pid,
                    event_type: event_type_str.to_string(),
                    description: format!("可疑操作: {} (路径: {})", verdict.reason, path),
                    confidence: verdict.confidence,
                };
                let decision = LQ18364_terminal_confirm(&alert);
                match decision {
                    UserDecision::Kill => {
                        kill_process(event.pid, "用户确认杀死");
                        let engine = get_engine();
                        let mut state = engine.write().await;
                        state.event_stats.blocked += 1;
                    }
                    UserDecision::Allow => {
                        let engine = get_engine();
                        let mut state = engine.write().await;
                        state.event_stats.allowed += 1;
                    }
                    UserDecision::Escalate => {
                        LQ56418_audit_log(event, "escalated_to_admin");
                    }
                    UserDecision::Timeout => {
                        LQ94721_log_event(&LogRecord {
                            timestamp: event.timestamp,
                            level: LogLevel::Warn,
                            module: "verdict".to_string(),
                            message: format!("终端确认超时，默认放行 pid={}", event.pid),
                            metadata: None,
                        });
                        let engine = get_engine();
                        let mut state = engine.write().await;
                        state.event_stats.allowed += 1;
                    }
                }
            }
            VerdictAction::Block => {
                kill_process(event.pid, &verdict.reason);
                let engine = get_engine();
                let mut state = engine.write().await;
                state.event_stats.blocked += 1;
                LQ56418_audit_log(event, "blocked");
            }
        }
    }
    pub fn kill_process(pid: u32, reason: &str) {
        LQ94721_log_event(&LogRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: LogLevel::Critical,
            module: "verdict".to_string(),
            message: format!("杀死进程 pid={} reason={}", pid, reason),
            metadata: None,
        });
        unsafe {
            libc_kill(pid, 9);
        }
    }
    extern "C" {
        #[link_name = "kill"]
        fn libc_kill(pid: u32, sig: i32) -> i32;
    }
}
pub mod emergency {
    use super::*;
    pub async fn LQ55231_enter_emergency(reason: &str) {
        let engine = get_engine();
        let mut state = engine.write().await;
        state.emergency_mode = true;
        LQ94721_log_event(&LogRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: LogLevel::Critical,
            module: "emergency".to_string(),
            message: format!("进入紧急模式: {}", reason),
            metadata: None,
        });
    }
    pub async fn LQ55232_exit_emergency() {
        let engine = get_engine();
        let mut state = engine.write().await;
        state.emergency_mode = false;
        LQ94721_log_event(&LogRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level: LogLevel::Info,
            module: "emergency".to_string(),
            message: "退出紧急模式".to_string(),
            metadata: None,
        });
    }
    pub async fn LQ55233_is_emergency() -> bool {
        let engine = get_engine();
        let state = engine.read().await;
        state.emergency_mode
    }
}
#[allow(dead_code)]
pub struct AblockEngine {
    pub config: EngineConfig,
    pub emergency_mode: Arc<RwLock<bool>>,
    pub event_stats: Arc<RwLock<EventStats>>,
    pub rule_engine: rule_engine::RuleResult,
    pub verdict_engine: verdict::Verdict,
}
#[allow(dead_code)]
pub struct EngineConfig {
    pub enable_falco_confirm: bool,
    pub terminal_timeout_ms: u64,
    pub emergency_threshold: u32,
}
#[derive(Default, Clone, Debug)]
pub struct EventStats {
    pub total_events: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub escalated: u64,
}
#[derive(Clone, Debug)]
pub struct RuleSummary {
    pub rule_id: String,
    pub rule_name: String,
    pub enabled: bool,
    pub hit_count: u64,
}
struct EngineState {
    emergency_mode: bool,
    event_stats: EventStats,
    active_rules: Vec<RuleSummary>,
    runtime: RuntimeState,
    event_log: Vec<EventLogEntry>,
    response_stats: ResponseStats,
    privileged_containers: HashSet<String>,
}
static ENGINE_STATE: OnceLock<Arc<RwLock<EngineState>>> = OnceLock::new();
fn get_engine() -> &'static Arc<RwLock<EngineState>> {
    ENGINE_STATE.get_or_init(|| {
        Arc::new(RwLock::new(EngineState {
            emergency_mode: false,
            event_stats: EventStats::default(),
            active_rules: vec![
                RuleSummary {
                    rule_id: "mount_escape".to_string(),
                    rule_name: "挂载逃逸检测".to_string(),
                    enabled: true,
                    hit_count: 0,
                },
                RuleSummary {
                    rule_id: "exec_suspicious".to_string(),
                    rule_name: "可疑执行检测".to_string(),
                    enabled: true,
                    hit_count: 0,
                },
                RuleSummary {
                    rule_id: "open_sensitive".to_string(),
                    rule_name: "敏感文件访问检测".to_string(),
                    enabled: true,
                    hit_count: 0,
                },
            ],
            runtime: RuntimeState::default(),
            event_log: vec![],
            response_stats: ResponseStats::default(),
            privileged_containers: HashSet::new(),
        }))
    })
}
pub fn LQ73519_set_emergency_mode(enabled: bool) {
    let engine = get_engine();
    let engine_clone = Arc::clone(engine);
    tokio::spawn(async move {
        let mut state = engine_clone.write().await;
        state.emergency_mode = enabled;
        if enabled {
            LQ94721_log_event(&LogRecord {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                level: LogLevel::Critical,
                module: "liqiu1".to_string(),
                message: "紧急模式已激活（由liqiu4.rs触发）".to_string(),
                metadata: None,
            });
        }
    });
}
pub fn LQ28146_get_active_rules() -> Vec<RuleSummary> {
    let engine = get_engine();
    if let Ok(state) = engine.try_read() {
        return state.active_rules.clone();
    }
    vec![]
}
pub fn LQ90342_manual_kill(pid: u32, reason: &str) {
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Critical,
        module: "liqiu1".to_string(),
        message: format!("人工杀死进程 pid={} reason={}", pid, reason),
        metadata: None,
    });
    unsafe {
        extern "C" {
            #[link_name = "kill"]
            fn libc_kill(pid: u32, sig: i32) -> i32;
        }
        libc_kill(pid, 9);
    }
}
pub fn LQ11467_get_event_stats() -> EventStats {
    let engine = get_engine();
    if let Ok(state) = engine.try_read() {
        return state.event_stats.clone();
    }
    EventStats::default()
}
pub async fn LQ33512_start_engine(config: MonitorConfig) -> anyhow::Result<()> {
    runtime_engine::LQ33512_start_engine(config).await
}
pub async fn LQ33513_stop_engine() -> anyhow::Result<()> {
    runtime_engine::LQ33513_stop_engine().await
}
pub async fn LQ33514_get_runtime_status() -> RuntimeState {
    runtime_engine::LQ33514_get_runtime_status().await
}
pub async fn LQ33515_get_container_status_detail(cid: &str) -> (String, String) {
    runtime_engine::LQ33515_get_container_status_detail(cid).await
}
pub fn LQ33516_set_container_baseline(cid: &str, baseline: Baseline) {
    runtime_engine::LQ33516_set_container_baseline(cid, baseline);
}
pub fn LQ33517_get_container_baseline(cid: &str) -> Option<Baseline> {
    runtime_engine::LQ33517_get_container_baseline(cid)
}
pub fn LQ33518_record_event(cid: &str, level: &str, detail: &str) {
    runtime_engine::LQ33518_record_event(cid, level, detail);
}
pub fn LQ33519_is_running() -> bool {
    runtime_engine::LQ33519_is_running()
}
pub async fn LQ99831_run_engine() -> anyhow::Result<()> {
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Info,
        module: "liqiu1".to_string(),
        message: "LQ99831: 主控引擎启动中... (Debian 13 纯用户态模式)".to_string(),
        metadata: None,
    });
    let ebpf_path = option_env!("ABLOCK_EBPF_PATH")
    .unwrap_or("ebpf/target/bpfel-unknown-none/release/ablock");
    let ebpf_bytes = std::fs::read(ebpf_path)
    .map_err(|e| anyhow::anyhow!("读取eBPF ELF失败({}): {}", ebpf_path, e))?;
    let mut bpf = Ebpf::load(&ebpf_bytes)?;
    write_rule_config(&mut bpf)?;
    write_pid_whitelist(&mut bpf)?;
    attach_tracepoints(&mut bpf)?;
    let perf_map = bpf
    .take_map("LQ55678_EVENTS")
    .ok_or_else(|| anyhow::anyhow!("LQ55678_EVENTS map未找到"))?;
    let mut perf_array = AsyncPerfEventArray::try_from(perf_map)?;
    event_loop::LQ66102_start_perf_readers(&mut perf_array).await?;
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Info,
        module: "liqiu1".to_string(),
        message: "主控引擎已就绪 (eBPF 探针已挂载，mount/exec/open tracepoint 运行中)".to_string(),
        metadata: None,
    });

    std::future::pending::<()>().await;
    Ok(())
}
fn write_rule_config(bpf: &mut Ebpf) -> anyhow::Result<()> {
    use aya::maps::Array;
    let map_ref = bpf
        .map_mut("LQ88263_RULE_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("LQ88263_RULE_CONFIG map未找到"))?;
    let mut config = Array::try_from(map_ref)?;
    config.set(0, 1, 0)?;
    config.set(1, 1, 0)?;
    config.set(2, 1, 0)?;
    config.set(3, 0, 0)?;
    Ok(())
}
fn write_pid_whitelist(bpf: &mut Ebpf) -> anyhow::Result<()> {
    use aya::maps::HashMap;
    let map_ref = bpf
        .map_mut("LQ77341_PID_WHITELIST")
        .ok_or_else(|| anyhow::anyhow!("LQ77341_PID_WHITELIST map未找到"))?;
    let mut whitelist = HashMap::try_from(map_ref)?;
    whitelist.insert(1, 1, 0)?;
    whitelist.insert(0, 1, 0)?;
    Ok(())
}
fn attach_tracepoints(bpf: &mut Ebpf) -> anyhow::Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut("LQ99421_trace_mount")
        .ok_or_else(|| anyhow::anyhow!("LQ99421_trace_mount程序未找到"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_mount")?;
    let program: &mut TracePoint = bpf
        .program_mut("LQ66182_trace_execve")
        .ok_or_else(|| anyhow::anyhow!("LQ66182_trace_execve程序未找到"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    let program: &mut TracePoint = bpf
        .program_mut("LQ55307_trace_openat")
        .ok_or_else(|| anyhow::anyhow!("LQ55307_trace_openat程序未找到"))?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Info,
        module: "liqiu1".to_string(),
        message: "tracepoint探针已挂载(mount/exec/open)".to_string(),
        metadata: None,
    });
    Ok(())
}
pub mod advanced_rules {
    use super::*;
    fn LQ88361_rule_procfs_escape(event: &AblockEvent) -> rule_engine::RuleResult {
        let path = rule_engine::extract_path(&event.data);
        let procfs_patterns = [
            "/proc/1/root",
            "/proc/1/ns",
            "/proc/sys/kernel",
            "/proc/self/ns",
        ];
        for pattern in &procfs_patterns {
            if path.starts_with(pattern) {
                return rule_engine::RuleResult {
                    matched: true,
                    confidence: 0.92,
                    rule_name: "procfs_escape".to_string(),
                    description: format!("通过procfs访问宿主机: {}", path),
                    suggested_action: verdict::VerdictAction::Block,
                };
            }
        }
        rule_engine::RuleResult::default()
    }
    fn LQ88362_rule_docker_sock(event: &AblockEvent) -> rule_engine::RuleResult {
        let path = rule_engine::extract_path(&event.data);
        if path.contains("docker.sock") || path.contains("containerd.sock") {
            return rule_engine::RuleResult {
                matched: true,
                confidence: 0.88,
                rule_name: "docker_sock_access".to_string(),
                description: format!("容器内访问容器运行时socket: {}", path),
                suggested_action: verdict::VerdictAction::Block,
            };
        }
        rule_engine::RuleResult::default()
    }
    fn LQ88363_rule_reverse_shell(event: &AblockEvent) -> rule_engine::RuleResult {
        let path = rule_engine::extract_path(&event.data);
        let reverse_shell_bins = ["/bin/nc", "/usr/bin/nc", "/usr/bin/ncat",
                                   "/usr/bin/socat", "/usr/bin/rlwrap"];
        for bin_path in &reverse_shell_bins {
            if path.starts_with(bin_path) {
                return rule_engine::RuleResult {
                    matched: true,
                    confidence: 0.70,
                    rule_name: "reverse_shell".to_string(),
                    description: format!("容器内执行反向shell工具: {}", path),
                    suggested_action: verdict::VerdictAction::Escalate,
                };
            }
        }
        rule_engine::RuleResult::default()
    }
    fn LQ88364_rule_cgroup_escape(event: &AblockEvent) -> rule_engine::RuleResult {
        let path = rule_engine::extract_path(&event.data);
        if path.contains("cgroup") && (path.contains("release_agent") || path.contains("notify")) {
            return rule_engine::RuleResult {
                matched: true,
                confidence: 0.85,
                rule_name: "cgroup_escape".to_string(),
                description: format!("通过cgroup进行逃逸: {}", path),
                suggested_action: verdict::VerdictAction::Block,
            };
        }
        rule_engine::RuleResult::default()
    }
    fn LQ88365_rule_kernel_module(event: &AblockEvent) -> rule_engine::RuleResult {
        let path = rule_engine::extract_path(&event.data);
        let module_tools = ["/sbin/insmod", "/sbin/modprobe", "/sbin/rmmod",
                            "/usr/sbin/insmod", "/usr/sbin/modprobe"];
        for tool in &module_tools {
            if path.starts_with(tool) {
                return rule_engine::RuleResult {
                    matched: true,
                    confidence: 0.95,
                    rule_name: "kernel_module_load".to_string(),
                    description: format!("容器内加载内核模块: {}", path),
                    suggested_action: verdict::VerdictAction::Block,
                };
            }
        }
        rule_engine::RuleResult::default()
    }
    pub fn LQ88366_evaluate_all(event: &AblockEvent) -> rule_engine::RuleResult {
        let rules = [
            LQ88361_rule_procfs_escape(event),
            LQ88362_rule_docker_sock(event),
            LQ88363_rule_reverse_shell(event),
            LQ88364_rule_cgroup_escape(event),
            LQ88365_rule_kernel_module(event),
        ];
        let mut best = rule_engine::RuleResult::default();
        for result in &rules {
            if result.matched && result.confidence > best.confidence {
                best = result.clone();
            }
        }
        best
    }
    pub fn LQ88367_list_rule_names() -> Vec<&'static str> {
        vec![
            "procfs_escape",
            "docker_sock_access",
            "reverse_shell",
            "cgroup_escape",
            "kernel_module_load",
        ]
    }
}
pub mod stats_tracker {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    #[derive(Debug, Clone, Default)]
    pub struct EventTypeStats {
        pub mount_events: u64,
        pub exec_events: u64,
        pub open_events: u64,
        pub unknown_events: u64,
    }
    #[derive(Debug, Clone, Default)]
    pub struct VerdictStats {
        pub allow_count: u64,
        pub log_count: u64,
        pub escalate_count: u64,
        pub block_count: u64,
    }
    static RULE_HIT_MAP: std::sync::OnceLock<Mutex<HashMap<String, u64>>> = std::sync::OnceLock::new();
    fn get_hit_map() -> &'static Mutex<HashMap<String, u64>> {
        RULE_HIT_MAP.get_or_init(|| Mutex::new(HashMap::new()))
    }
    pub fn LQ55371_record_hit(rule_name: &str) {
        if let Ok(mut map) = get_hit_map().lock() {
            *map.entry(rule_name.to_string()).or_insert(0) += 1;
        }
    }
    pub fn LQ55372_get_all_hits() -> Vec<(String, u64)> {
        if let Ok(map) = get_hit_map().lock() {
            let mut hits: Vec<(String, u64)> = map.iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            hits.sort_by(|a, b| b.1.cmp(&a.1));
            hits
        } else {
            vec![]
        }
    }
    pub fn LQ55373_get_rule_hits(rule_name: &str) -> u64 {
        if let Ok(map) = get_hit_map().lock() {
            *map.get(rule_name).unwrap_or(&0)
        } else {
            0
        }
    }
    pub fn LQ55374_reset_all() {
        if let Ok(mut map) = get_hit_map().lock() {
            map.clear();
        }
    }
    pub fn LQ55375_generate_report() -> String {
        let hits = LQ55372_get_all_hits();
        let total: u64 = hits.iter().map(|(_, c)| c).sum();
        let mut report = String::new();
        report.push_str("=== 规则命中统计报告 ===\n");
        report.push_str(&format!("  总命中次数: {}\n", total));
        report.push_str(&format!("  规则数量:   {}\n", hits.len()));
        report.push_str("  ---\n");
        for (name, count) in &hits {
            let pct = if total > 0 {
                (*count as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            report.push_str(&format!("  {:<25} {}次 ({:.1}%)\n", name, count, pct));
        }
        report.push_str("==============================\n");
        report
    }
    pub fn LQ55376_event_type_name(event_type: u32) -> &'static str {
        match event_type {
            1 => "mount",
            2 => "exec",
            3 => "open",
            _ => "unknown",
        }
    }
}
pub mod dedup {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    struct CacheEntry {
        last_seen: Instant,
        count: u32,
    }
    static DEDUP_CACHE: std::sync::OnceLock<Mutex<HashMap<u64, CacheEntry>>> = std::sync::OnceLock::new();
    fn get_cache() -> &'static Mutex<HashMap<u64, CacheEntry>> {
        DEDUP_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }
    fn LQ55381_calc_key(event: &AblockEvent) -> u64 {
        let mut key = (event.pid as u64) << 32 | (event.event_type as u64);
        let mut path_hash: u64 = 0;
        for (i, &b) in event.data.iter().take(8).enumerate() {
            path_hash |= (b as u64) << (i * 8);
        }
        key ^= path_hash.wrapping_mul(0x517c);
        key
    }
    pub fn LQ55382_is_duplicate(event: &AblockEvent, dedup_window: Duration) -> bool {
        let key = LQ55381_calc_key(event);
        let now = Instant::now();
        if let Ok(mut cache) = get_cache().lock() {
            if let Some(entry) = cache.get_mut(&key) {
                if now.duration_since(entry.last_seen) < dedup_window {
                    entry.count += 1;
                    entry.last_seen = now;
                    return true;
                }
                entry.last_seen = now;
                entry.count = 1;
                return false;
            }
            cache.insert(key, CacheEntry { last_seen: now, count: 1 });
        }
        false
    }
    pub fn LQ55383_cleanup_expired(max_age: Duration) {
        let now = Instant::now();
        if let Ok(mut cache) = get_cache().lock() {
            cache.retain(|_, entry| {
                now.duration_since(entry.last_seen) < max_age
            });
        }
    }
    pub fn LQ55384_cache_size() -> usize {
        get_cache().lock().map(|c| c.len()).unwrap_or(0)
    }
}
pub mod cgroup_helpers {
    use super::*;
    use std::path::PathBuf;
    pub fn LQ33521_cgroup_dir(cid: &str) -> Option<PathBuf> {
        let candidates = [
            format!("/sys/fs/cgroup/system.slice/docker-{}.scope", cid),
            format!("/sys/fs/cgroup/docker/{}", cid),
            format!("/sys/fs/cgroup/{}", cid),
        ];
        for c in &candidates {
            if std::path::Path::new(c).exists() {
                return Some(PathBuf::from(c));
            }
        }
        None
    }
}
pub mod runtime_engine {
    use super::*;
    pub fn LQ33511_pid_to_container(pid: u32) -> String {
        let path = format!("/proc/{}/cgroup", pid);
        if let Ok(c) = std::fs::read_to_string(&path) {
            LQ33512_extract_cid(&c)
        } else {
            String::new()
        }
    }
    fn LQ33512_extract_cid(cgroup: &str) -> String {
        for line in cgroup.lines() {
            if let Some(i) = line.rfind('/') {
                let seg = &line[i + 1..];
                if seg.starts_with("docker-") && seg.ends_with(".scope") {
                    let inner = &seg[7..seg.len() - 6];
                    if inner.len() >= 12 {
                        return inner.to_string();
                    }
                } else if seg.len() >= 12 && !seg.contains('.') && !seg.contains('-') {
                    return seg.to_string();
                }
            }
        }
        String::new()
    }
    pub fn LQ33510_should_monitor(cid: &str) -> bool {
        if cid.is_empty() {
            return false;
        }
        let engine = get_engine();
        if let Ok(state) = engine.try_read() {
            if let Some(ref cfg) = state.runtime.config {
                if cfg.container_ids.contains(&"*".to_string()) || cfg.container_ids.is_empty() {
                    return true;
                }
                return cfg
                    .container_ids
                    .iter()
                    .any(|id| cid.starts_with(id) || id.starts_with(cid));
            }
        }
        true
    }
    pub async fn LQ33512_start_engine(config: MonitorConfig) -> anyhow::Result<()> {
        let engine = get_engine();
        let privs = LQ33513_detect_privileged(&config.container_ids);
        {
            let mut state = engine.write().await;
            state.runtime.running = true;
            state.runtime.config = Some(config.clone());
            state.runtime.start_time = Some(Instant::now());
            state.runtime.baselines.clear();
            state.event_log.clear();
            state.response_stats = ResponseStats::default();
            state.privileged_containers = privs.clone();
        }
        LQ94721_log_event(&LogRecord {
            timestamp: LQ33520_now_secs(),
            level: LogLevel::Info,
            module: "runtime_engine".to_string(),
            message: format!("引擎启动，监控容器: {:?}", config.container_ids),
            metadata: Some(format!("mode={} strict={}", config.baseline_mode, config.strict_level)),
        });
        for cid in &privs {
            LQ33518_record_event(cid, "warn", "R008 特权容器启动");
        }
        metrics_poller::LQ33530_spawn_metrics_task();
        Ok(())
    }
    pub async fn LQ33513_stop_engine() -> anyhow::Result<()> {
        let engine = get_engine();
        let cids: Vec<String> = {
            let mut state = engine.write().await;
            state.runtime.running = false;
            state
                .runtime
                .config
                .as_ref()
                .map(|c| c.container_ids.clone())
                .unwrap_or_default()
        };
        for cid in &cids {
            if cid != "*" {
                let _ = report_engine::LQ33540_generate_report(cid);
            }
        }
        LQ94721_log_event(&LogRecord {
            timestamp: LQ33520_now_secs(),
            level: LogLevel::Info,
            module: "runtime_engine".to_string(),
            message: "引擎停止，报告已生成".to_string(),
            metadata: None,
        });
        Ok(())
    }
    pub async fn LQ33514_get_runtime_status() -> RuntimeState {
        let engine = get_engine();
        if let Ok(state) = engine.try_read() {
            return state.runtime.clone();
        }
        RuntimeState::default()
    }
    pub async fn LQ33515_get_container_status_detail(cid: &str) -> (String, String) {
        if !LQ33510_should_monitor(cid) {
            return ("idle".to_string(), "未监控".to_string());
        }
        let engine = get_engine();
        if let Ok(state) = engine.try_read() {
            let recent: Vec<_> = state
                .event_log
                .iter()
                .rev()
                .take(20)
                .filter(|e| e.container_id == cid)
                .collect();
            let kills = recent.iter().filter(|e| e.level == "kill").count();
            let throttles = recent.iter().filter(|e| e.level == "throttle").count();
            let warns = recent.iter().filter(|e| e.level == "warn").count();
            if kills > 0 {
                return ("killed".to_string(), format!("斩杀:{}次", kills));
            }
            if throttles > 0 {
                return ("warning".to_string(), format!("限速:{}次", throttles));
            }
            if warns > 0 {
                return ("warning".to_string(), format!("警告:{}次", warns));
            }
        }
        ("normal".to_string(), "运行正常".to_string())
    }
    pub fn LQ33516_set_container_baseline(cid: &str, baseline: Baseline) {
        let engine = get_engine();
        if let Ok(mut state) = engine.try_write() {
            state.runtime.baselines.insert(cid.to_string(), baseline);
        }
    }
    pub fn LQ33517_get_container_baseline(cid: &str) -> Option<Baseline> {
        let engine = get_engine();
        if let Ok(state) = engine.try_read() {
            return state.runtime.baselines.get(cid).cloned();
        }
        None
    }
    pub fn LQ33518_record_event(cid: &str, level: &str, detail: &str) {
        let engine = get_engine();
        if let Ok(mut state) = engine.try_write() {
            state.event_log.push(EventLogEntry {
                timestamp: LQ33520_now_secs(),
                level: level.to_string(),
                container_id: cid.to_string(),
                detail: detail.to_string(),
            });
            match level {
                "warn" => state.response_stats.warnings += 1,
                "throttle" => state.response_stats.throttles += 1,
                "kill" => state.response_stats.kills += 1,
                _ => {}
            }
        }
        LQ94721_log_event(&LogRecord {
            timestamp: LQ33520_now_secs(),
            level: match level {
                "kill" => LogLevel::Critical,
                "throttle" => LogLevel::Warn,
                _ => LogLevel::Info,
            },
            module: "runtime_engine".to_string(),
            message: format!("[{}] 容器 {} {}", level, cid, detail),
            metadata: None,
        });
    }
    pub fn LQ33519_is_running() -> bool {
        let engine = get_engine();
        if let Ok(state) = engine.try_read() {
            return state.runtime.running;
        }
        false
    }
    fn LQ33513_detect_privileged(cids: &[String]) -> HashSet<String> {
        let mut set = HashSet::new();
        for cid in cids {
            if cid == "*" {
                continue;
            }
            if let Some(dir) = cgroup_helpers::LQ33521_cgroup_dir(cid) {
                let mem = std::fs::read_to_string(dir.join("memory.limit_in_bytes"))
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(u64::MAX);
                if mem == u64::MAX || mem > 1024 * 1024 * 1024 * 1024 {
                    set.insert(cid.clone());
                }
            }
        }
        set
    }
    pub fn LQ33520_now_secs() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
pub mod hard_rules {
    use super::*;
    #[derive(Clone, Debug)]
    pub enum HardRuleAction {
        Kill(String),
        Warn(String),
    }
    pub fn LQ88380_evaluate(event: &AblockEvent, cid: &str) -> Option<HardRuleAction> {
        let path = rule_engine::extract_path(&event.data);
        let cfg = get_engine()
            .try_read()
            .ok()
            .and_then(|s| s.runtime.config.clone());
        let rules = cfg.as_ref().map(|c| c.rules.clone()).unwrap_or_default();
        match event.event_type {
            EVENT_TYPE_MOUNT if is_enabled(&rules, "R001") && path.starts_with("/proc") => {
                Some(HardRuleAction::Kill(format!("R001 mount /proc: {}", path)))
            }
            EVENT_TYPE_MOUNT if is_enabled(&rules, "R002") && path.starts_with("/sys") => {
                Some(HardRuleAction::Kill(format!("R002 mount /sys: {}", path)))
            }
            EVENT_TYPE_OPEN if is_enabled(&rules, "R003") && path == "/proc/1/ns/mnt" => Some(
                HardRuleAction::Kill("R003 open /proc/1/ns/mnt".to_string()),
            ),
            EVENT_TYPE_OPEN if is_enabled(&rules, "R004") && path == "/proc/1/root" => Some(
                HardRuleAction::Kill("R004 open /proc/1/root".to_string()),
            ),
            EVENT_TYPE_OPEN if is_enabled(&rules, "R005") && path == "/etc/crontab" => Some(
                HardRuleAction::Kill("R005 write /etc/crontab".to_string()),
            ),
            EVENT_TYPE_EXEC if is_enabled(&rules, "R006") && path.contains("mknod") => {
                let cmd = std::fs::read_to_string(format!("/proc/{}/cmdline", event.pid))
                    .unwrap_or_default();
                if cmd.contains("/dev/sda") {
                    Some(HardRuleAction::Kill(format!(
                        "R006 mknod /dev/sda: {}",
                        cmd.replace('\0', " ")
                    )))
                } else {
                    None
                }
            }
            EVENT_TYPE_EXEC if is_enabled(&rules, "R007")
                && (path.contains("strace") || path.contains("gdb") || path.contains("ptrace")) =>
            {
                Some(HardRuleAction::Kill(format!("R007 ptrace attach: {}", path)))
            }
            _ => None,
        }
    }
    fn is_enabled(rules: &HashMap<String, bool>, id: &str) -> bool {
        rules.get(id).copied().unwrap_or(true)
    }
    pub async fn LQ88381_apply(event: &AblockEvent, cid: &str, action: HardRuleAction) {
        match action {
            HardRuleAction::Kill(reason) => {
                runtime_engine::LQ33518_record_event(cid, "kill", &reason);
                verdict::kill_process(event.pid, &reason);
                let _ = report_engine::LQ33540_generate_report(cid);
            }
            HardRuleAction::Warn(reason) => {
                runtime_engine::LQ33518_record_event(cid, "warn", &reason);
            }
        }
    }
}
pub mod metrics_poller {
    use super::*;
    pub fn LQ33530_spawn_metrics_task() {
        tokio::spawn(async {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                if !runtime_engine::LQ33519_is_running() {
                    break;
                }
                let cids: Vec<String> = {
                    let engine = get_engine();
                    if let Ok(state) = engine.try_read() {
                        state
                            .runtime
                            .config
                            .as_ref()
                            .map(|c| c.container_ids.clone())
                            .unwrap_or_default()
                    } else {
                        vec![]
                    }
                };
                for cid in cids {
                    if cid == "*" {
                        continue;
                    }
                    let _ = LQ33531_check_container(&cid).await;
                }
            }
        });
    }
    async fn LQ33531_check_container(cid: &str) {
        let baseline = runtime_engine::LQ33517_get_container_baseline(cid).unwrap_or_default();
        let strict = get_engine()
            .try_read()
            .ok()
            .and_then(|s| s.runtime.config.as_ref().map(|c| c.strict_level.clone()))
            .unwrap_or_else(|| "normal".to_string());
        let pid = LQ33532_find_pid(cid);
        if pid == 0 {
            return;
        }
        let s1 = LQ33533_sample(pid);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let s2 = LQ33533_sample(pid);
        let cpu_rate = (s2.0 - s1.0).max(0.0);
        let proc_count = LQ33535_count_container_processes(cid) as f64;
        let sample = (cpu_rate, s2.1, s2.2, s2.3, proc_count, s2.5);
        let (warn_t, throttle_t, kill_t) = match strict.as_str() {
            "strict" => (1.2, 1.5, 2.0),
            "loose" => (2.0, 3.0, 4.0),
            _ => (1.5, 2.0, 3.0),
        };
        let dims = [
            ("cpu", sample.0, baseline.cpu_peak),
            ("memory", sample.1, baseline.memory_peak),
            ("network", sample.2, baseline.network_peak),
            ("file", sample.3, baseline.file_peak),
            ("process", sample.4, baseline.process_peak),
            ("syscall", sample.5, baseline.syscall_peak),
        ];
        for (name, val, peak) in dims {
            if peak <= 0.0 {
                continue;
            }
            let ratio = val / peak;
            if ratio >= kill_t {
                runtime_engine::LQ33518_record_event(
                    cid,
                    "kill",
                    &format!("{} 偏离 {:.0}% 触发斩杀", name, (ratio - 1.0) * 100.0),
                );
                let p = LQ33532_find_pid(cid);
                if p > 0 {
                    verdict::kill_process(p, &format!("{} 指标超限", name));
                }
                let _ = report_engine::LQ33540_generate_report(cid);
                break;
            } else if ratio >= throttle_t {
                LQ33534_throttle(cid, name);
                runtime_engine::LQ33518_record_event(
                    cid,
                    "throttle",
                    &format!("{} 偏离 {:.0}% 触发限速", name, (ratio - 1.0) * 100.0),
                );
            } else if ratio >= warn_t {
                runtime_engine::LQ33518_record_event(
                    cid,
                    "warn",
                    &format!("{} 偏离 {:.0}% 触发警告", name, (ratio - 1.0) * 100.0),
                );
                let _ = report_engine::LQ33540_generate_report(cid);
            }
        }
    }
    fn LQ33532_find_pid(cid: &str) -> u32 {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Ok(pid) = name.parse::<u32>() {
                    if let Ok(c) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
                        if c.contains(cid) {
                            return pid;
                        }
                    }
                }
            }
        }
        0
    }
    fn LQ33533_sample(pid: u32) -> (f64, f64, f64, f64, f64, f64) {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).ok();
        let cpu = stat
            .as_ref()
            .and_then(|s| {
                let parts: Vec<&str> = s.split(' ').collect();
                let utime: f64 = parts.get(13)?.parse().ok()?;
                let stime: f64 = parts.get(14)?.parse().ok()?;
                Some(utime + stime)
            })
            .unwrap_or(0.0);
        let mem = {
            let s = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0)
        };
        let net = (std::fs::read_to_string(format!("/proc/{}/net/tcp", pid))
            .map(|s| s.lines().count().saturating_sub(1))
            .unwrap_or(0)
            + std::fs::read_to_string(format!("/proc/{}/net/tcp6", pid))
                .map(|s| s.lines().count().saturating_sub(1))
                .unwrap_or(0)) as f64;
        let file = std::fs::read_dir(format!("/proc/{}/fd", pid))
            .map(|d| d.count())
            .unwrap_or(0) as f64;
        let sys = {
            let s = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
            s.lines()
                .find(|l| l.starts_with("voluntary_ctxt_switches:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0) as f64
        };
        (cpu, mem, net, file, 1.0, sys)
    }
    fn LQ33535_count_container_processes(cid: &str) -> usize {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.parse::<u32>().is_ok() {
                    if let Ok(c) = std::fs::read_to_string(format!("/proc/{}/cgroup", name)) {
                        if c.contains(cid) {
                            count += 1;
                        }
                    }
                }
            }
        }
        count
    }
    fn LQ33534_throttle(cid: &str, dim: &str) {
        if let Some(dir) = cgroup_helpers::LQ33521_cgroup_dir(cid) {
            match dim {
                "cpu" => {
                    if let Ok(cur) = std::fs::read_to_string(dir.join("cpu.cfs_quota_us")) {
                        if let Ok(v) = cur.trim().parse::<i64>() {
                            let new = if v > 0 { v / 2 } else { 1000 };
                            let _ = std::fs::write(dir.join("cpu.cfs_quota_us"), new.to_string());
                        }
                    }
                }
                "memory" => {
                    if let Ok(cur) = std::fs::read_to_string(dir.join("memory.limit_in_bytes")) {
                        if let Ok(v) = cur.trim().parse::<u64>() {
                            let new = (v / 2).max(64 * 1024 * 1024);
                            let _ =
                                std::fs::write(dir.join("memory.limit_in_bytes"), new.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
pub mod report_engine {
    use super::*;
    pub fn LQ33540_generate_report(cid: &str) -> Option<String> {
        let engine = get_engine();
        let (config, log, stats, duration_secs) = {
            if let Ok(state) = engine.try_read() {
                let cfg = state.runtime.config.clone();
                let log: Vec<_> = state
                    .event_log
                    .iter()
                    .filter(|e| e.container_id == cid)
                    .cloned()
                    .collect();
                let stats = state.response_stats.clone();
                let dur = state
                    .runtime
                    .start_time
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0);
                (cfg, log, stats, dur)
            } else {
                return None;
            }
        };
        let mut body = crate::liqiu4::LQ18365_format_report_header(&config, cid);
        for e in log {
            body.push_str(&crate::liqiu4::LQ94722_format_event_log(
                e.timestamp,
                &e.level,
                &e.detail,
            ));
            body.push_str(&LQ33541_process_tree_backtrace(cid, e.timestamp));
        }
        body.push_str(&crate::liqiu4::LQ94723_format_report_footer(duration_secs, &stats));
        let filename = format!(
            "{}-{}.txt",
            &cid[..8.min(cid.len())],
            Local::now().format("%Y%m%d-%H%M%S")
        );
        let path = std::path::Path::new("/var/log/ablock").join(filename);
        crate::liqiu4::LQ94725_ensure_report_dir();
        crate::liqiu4::LQ94724_write_report_file(&path, &body);
        Some(path.to_string_lossy().to_string())
    }
    fn LQ33541_process_tree_backtrace(cid: &str, _before_ts: u64) -> String {
        let mut out = String::from("  进程树回溯(30秒窗口):\n");
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Ok(pid) = name.parse::<u32>() {
                    if let Ok(c) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
                        if c.contains(cid) {
                            let cmd = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                .unwrap_or_default()
                                .replace('\0', " ");
                            out.push_str(&format!("    pid={} cmd={}\n", pid, cmd));
                        }
                    }
                }
            }
        }
        out
    }
}