use axum::{
    routing::{get, post},
    Router, Json,
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Any, AllowOrigin};
use tower_http::services::ServeDir;
use crate::liqiu1::{
    LQ33512_start_engine, LQ33513_stop_engine, LQ33514_get_runtime_status,
    LQ33515_get_container_status_detail, LQ33516_set_container_baseline,
    MonitorConfig as EngineConfig, Baseline as EngineBaseline,
};
use crate::liqiu4::{
    LQ94721_log_event, LogRecord, LogLevel,
    LQ94726_list_report_files, LQ94727_read_report_file,
};
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub status: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct MonitorConfig {
    pub container_ids: Vec<String>,
    pub baseline_mode: String,
    pub strict_level: String,
    pub rules: HashMap<String, bool>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct BaselineRequest {
    pub container_id: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct LimitsResponse {
    pub cpu_cores: f64,
    pub memory_mb: f64,
    pub pids_max: i64,
}
#[derive(Serialize, Clone)]
pub struct MonitorStatus {
    pub running: bool,
    pub containers: Vec<ContainerStatus>,
}
#[derive(Serialize, Clone)]
pub struct ContainerStatus {
    pub id: String,
    pub name: String,
    pub status: String,
    pub detail: String,
}
fn ok<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        code: 0,
        message: "success".to_string(),
        data: Some(data),
    })
}
fn err<T: Serialize>(msg: &str) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        code: 1,
        message: msg.to_string(),
        data: None,
    })
}
pub struct ApiState {
    pub monitor_running: bool,
    pub monitored_containers: Vec<String>,
}
static API_STATE: std::sync::OnceLock<Arc<RwLock<ApiState>>> = std::sync::OnceLock::new();
fn get_state() -> &'static Arc<RwLock<ApiState>> {
    API_STATE.get_or_init(|| {
        Arc::new(RwLock::new(ApiState {
            monitor_running: false,
            monitored_containers: vec![],
        }))
    })
}
fn LQ99121_discover_containers() -> Vec<ContainerInfo> {
    let mut map: HashMap<String, ContainerInfo> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_ok() {
                let path = format!("/proc/{}/cgroup", name);
                if let Ok(c) = std::fs::read_to_string(&path) {
                    if let Some(id) = LQ99122_extract_container_id(&c) {
                        map.entry(id.clone()).or_insert_with(|| ContainerInfo {
                            id: id.clone(),
                            name: id[..8.min(id.len())].to_string(),
                            status: "running".to_string(),
                        });
                    }
                }
            }
        }
    }
    let mut v: Vec<_> = map.into_values().collect();
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v
}
fn LQ99122_extract_container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        if let Some(i) = line.rfind('/') {
            let seg = &line[i + 1..];
            if seg.starts_with("docker-") && seg.ends_with(".scope") {
                let inner = &seg[7..seg.len() - 6];
                if inner.len() >= 12 {
                    return Some(inner.to_string());
                }
            } else if seg.len() >= 12 && !seg.contains('.') && !seg.contains('-') {
                return Some(seg.to_string());
            }
        }
    }
    None
}
fn LQ99123_cgroup_dir(cid: &str) -> Option<std::path::PathBuf> {
    let candidates = [
        format!("/sys/fs/cgroup/system.slice/docker-{}.scope", cid),
        format!("/sys/fs/cgroup/docker/{}", cid),
        format!("/sys/fs/cgroup/{}", cid),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Some(std::path::Path::new(c).to_path_buf());
        }
    }
    None
}
fn LQ99124_read_file_u64(p: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}
fn LQ99125_read_file_i64(p: &std::path::Path) -> Option<i64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}
fn LQ99126_read_file_string(p: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}
async fn LQ99111_get_containers() -> Json<ApiResponse<Vec<ContainerInfo>>> {
    ok(LQ99121_discover_containers())
}
async fn LQ99127_get_container_limits(
    Path(cid): Path<String>,
) -> Json<ApiResponse<LimitsResponse>> {
    let dir = match LQ99123_cgroup_dir(&cid) {
        Some(d) => d,
        None => return err("未找到容器 cgroup"),
    };
    let mem = LQ99124_read_file_u64(&dir.join("memory.limit_in_bytes")).unwrap_or(0);
    let quota = LQ99125_read_file_i64(&dir.join("cpu.cfs_quota_us")).unwrap_or(-1);
    let period = LQ99125_read_file_i64(&dir.join("cpu.cfs_period_us")).unwrap_or(100000);
    let pids = LQ99125_read_file_i64(&dir.join("pids.max")).unwrap_or(-1);
    let cpu_cores = if quota > 0 {
        quota as f64 / period.max(1) as f64
    } else {
        -1.0
    };
    ok(LimitsResponse {
        cpu_cores,
        memory_mb: (mem as f64) / (1024.0 * 1024.0),
        pids_max: pids,
    })
}
async fn LQ99115_quick_baseline(
    Json(req): Json<BaselineRequest>,
) -> Json<ApiResponse<HashMap<String, f64>>> {
    let cid = req.container_id;
    let dir = match LQ99123_cgroup_dir(&cid) {
        Some(d) => d,
        None => return err("未找到容器 cgroup"),
    };
    let mem_limit = LQ99124_read_file_u64(&dir.join("memory.limit_in_bytes")).unwrap_or(0) as f64;
    let quota = LQ99125_read_file_i64(&dir.join("cpu.cfs_quota_us")).unwrap_or(-1) as f64;
    let period = LQ99125_read_file_i64(&dir.join("cpu.cfs_period_us")).unwrap_or(100000) as f64;
    let max_cpu = if quota > 0.0 { quota / period } else { 0.0 };
    let pid = LQ99128_find_representative_pid(&cid);
    let start = if let Some(p) = pid {
        LQ99129_sample_pid(p)
    } else {
        (0.0, 0.0, 0, 0, 0, 0)
    };
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    let end = if let Some(p) = pid {
        LQ99129_sample_pid(p)
    } else {
        start
    };
    let cpu = if end.0 > start.0 {
        let raw = (end.0 - start.0) / 5.0;
        if max_cpu > 0.0 {
            raw.min(max_cpu * 100.0)
        } else {
            raw
        }
    } else {
        0.0
    };
    let mem = end.1;
    let net = end.2 as f64;
    let file = end.3 as f64;
    let proc_count = LQ99130_count_container_processes(&cid) as f64;
    let sys = end.5 as f64;
    let baseline = EngineBaseline {
        cpu_peak: cpu,
        memory_peak: mem,
        network_peak: net,
        file_peak: file,
        process_peak: proc_count,
        syscall_peak: sys,
    };
    LQ33516_set_container_baseline(&cid, baseline);
    let mut m = HashMap::new();
    m.insert("cpu".to_string(), cpu);
    m.insert("memory".to_string(), mem);
    m.insert("network".to_string(), net);
    m.insert("file".to_string(), file);
    m.insert("process".to_string(), proc_count);
    m.insert("syscall".to_string(), sys);
    ok(m)
}
fn LQ99128_find_representative_pid(cid: &str) -> Option<u32> {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(pid) = name.parse::<u32>() {
                if let Ok(c) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
                    if c.contains(cid) {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}
fn LQ99129_sample_pid(pid: u32) -> (f64, f64, usize, usize, usize, usize) {
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
    let net = std::fs::read_to_string(format!("/proc/{}/net/tcp", pid))
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0)
        + std::fs::read_to_string(format!("/proc/{}/net/tcp6", pid))
            .map(|s| s.lines().count().saturating_sub(1))
            .unwrap_or(0);
    let file = std::fs::read_dir(format!("/proc/{}/fd", pid))
        .map(|d| d.count())
        .unwrap_or(0);
    let sys = {
        let s = std::fs::read_to_string(format!("/proc/{}/status", pid)).unwrap_or_default();
        s.lines()
            .find(|l| l.starts_with("voluntary_ctxt_switches:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    (cpu, mem, net, file, 1, sys)
}
fn LQ99130_count_container_processes(cid: &str) -> usize {
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
async fn LQ99112_start_monitor(
    Json(config): Json<MonitorConfig>,
) -> Json<ApiResponse<String>> {
    if config.container_ids.is_empty() {
        return err("未选择容器");
    }
    let engine_config = EngineConfig {
        container_ids: config.container_ids.clone(),
        baseline_mode: config.baseline_mode.clone(),
        strict_level: config.strict_level.clone(),
        rules: config.rules.clone(),
    };
    match LQ33512_start_engine(engine_config).await {
        Ok(_) => {
            let state = get_state();
            let mut s = state.write().await;
            s.monitor_running = true;
            s.monitored_containers = config.container_ids;
            ok("监控已启动".to_string())
        }
        Err(e) => err(&format!("启动失败: {}", e)),
    }
}
async fn LQ99113_stop_monitor() -> Json<ApiResponse<String>> {
    match LQ33513_stop_engine().await {
        Ok(_) => {
            let state = get_state();
            let mut s = state.write().await;
            s.monitor_running = false;
            s.monitored_containers.clear();
            ok("监控已停止".to_string())
        }
        Err(e) => err(&format!("停止失败: {}", e)),
    }
}
async fn LQ99114_get_status() -> Json<ApiResponse<MonitorStatus>> {
    let runtime = LQ33514_get_runtime_status().await;
    let state = get_state().read().await;
    let mut containers = Vec::new();
    let all = LQ99121_discover_containers();
    let target: std::collections::HashSet<_> =
        state.monitored_containers.iter().cloned().collect();
    for c in all {
        if !state.monitor_running
            || target.contains(&c.id)
            || target.contains(&"*".to_string())
        {
            let detail = LQ33515_get_container_status_detail(&c.id).await;
            containers.push(ContainerStatus {
                id: c.id.clone(),
                name: c.name,
                status: detail.0,
                detail: detail.1,
            });
        }
    }
    ok(MonitorStatus {
        running: runtime.running,
        containers,
    })
}
async fn LQ99116_get_reports() -> Json<ApiResponse<Vec<String>>> {
    ok(LQ94726_list_report_files())
}
async fn LQ99130_get_report_content(Path(name): Path<String>) -> impl IntoResponse {
    if name.contains("..") || name.contains('/') {
        return (StatusCode::BAD_REQUEST, "非法文件名").into_response();
    }
    match LQ94727_read_report_file(&name) {
        Some(content) => (StatusCode::OK, content).into_response(),
        None => (StatusCode::NOT_FOUND, "报告不存在").into_response(),
    }
}
pub async fn LQ99101_start_api_server() -> anyhow::Result<()> {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::exact(
            "http://localhost:8080".parse::<axum::http::HeaderValue>().unwrap()
        ))
        .allow_methods(Any)
        .allow_headers(Any);
    let app = Router::new()
        .route("/api/containers", get(LQ99111_get_containers))
        .route("/api/container/:id/limits", get(LQ99127_get_container_limits))
        .route("/api/baseline/quick", post(LQ99115_quick_baseline))
        .route("/api/start", post(LQ99112_start_monitor))
        .route("/api/stop", post(LQ99113_stop_monitor))
        .route("/api/status", get(LQ99114_get_status))
        .route("/api/reports", get(LQ99116_get_reports))
        .route("/api/reports/:name", get(LQ99130_get_report_content))
        .layer(cors)
        .fallback_service(
            ServeDir::new("frontend/dist").append_index_html_on_directories(true),
        );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    eprintln!("🌐 API 服务器已启动: http://localhost:3000");
    eprintln!("🌐 前端地址: http://localhost:3000");
    LQ94721_log_event(&LogRecord {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        level: LogLevel::Info,
        module: "liqiu5".to_string(),
        message: "API 服务器启动".to_string(),
        metadata: None,
    });
    axum::serve(listener, app).await?;
    Ok(())
}