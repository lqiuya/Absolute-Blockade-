#![allow(
    non_snake_case,
    dead_code,
    unused_imports,
    unused_variables,
    unused_mut
)]
mod liqiu1;
mod liqiu5;
mod liqiu3;
mod liqiu4;
use clap::Parser;
use tokio::signal;
use crate::liqiu1::LQ99831_run_engine;
use crate::liqiu5::LQ99101_start_api_server;
use crate::liqiu4::{
    LQ65203_load_config, LQ94721_log_event, LQ34129_check_privilege,
    LogRecord, LogLevel,
};
#[derive(Parser, Debug)]
#[command(name = "ablock")]
#[command(about = "容器逃逸检测与阻断系统 - 基于eBPF的实时安全监控")]
#[command(version = "0.1.0")]
#[command(long_about = "ablock通过eBPF探针监控容器内的mount/exec/open系统调用，\
检测容器逃逸行为并提供终端交互式阻断能力。支持Falco外部确认、\
Trivy镜像扫描、审计日志记录，以及紧急模式全杀功能。")]
struct Cli {
    #[arg(short, long, default_value = "/etc/ablock/config.toml")]
    config: String,
    #[arg(short, long)]
    foreground: bool,
    #[arg(long)]
    check: bool,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    emergency: bool,
    #[arg(long)]
    no_privilege_check: bool,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    print_banner();
    if !cli.no_privilege_check && !LQ34129_check_privilege() {
        eprintln!("⚠️ 警告: 非root用户运行，阻断功能已禁用，仅记录模式");
        eprintln!("   提示: 使用 --no-privilege-check 跳过此检查（仅限测试）");
    }
    init_tracing(cli.verbose);
    let config = LQ65203_load_config(&cli.config);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    LQ94721_log_event(&LogRecord {
        timestamp: now_secs,
        level: LogLevel::Info,
        module: "main".to_string(),
        message: format!("ablock启动，配置文件: {}", cli.config),
        metadata: Some(format!(
            "foreground={}, verbose={}, emergency={}",
            cli.foreground, cli.verbose, cli.emergency
        )),
    });
    if cli.emergency {
        eprintln!("🚨 紧急模式启动！");
        crate::liqiu1::LQ73519_set_emergency_mode(true);
    }
    if cli.check {
        print_config_detail(&config);
        run_diagnostics(&cli);
        return Ok(());
    }
    if !cli.foreground {
        eprintln!("📝 守护进程模式（如需前台运行请加 --foreground）");
    }
    run_diagnostics(&cli);
    let api_task = tokio::spawn(async {
        if let Err(e) = LQ99101_start_api_server().await {
            eprintln!("❌ API 服务器异常退出: {:?}", e);
        }
    });
    let engine_task = tokio::spawn(async {
        if let Err(e) = LQ99831_run_engine().await {
            eprintln!("❌ 主控引擎异常退出: {:?}", e);
        }
    });
    tokio::select! {
        _ = engine_task => {
            eprintln!("主控引擎已停止");
        }
        _ = api_task => {
            eprintln!("API 服务器已停止");
        }
        _ = signal::ctrl_c() => {
            handle_shutdown("SIGINT (Ctrl+C)".to_string());
        }
        _ = recv_sigterm() => {
            handle_shutdown("SIGTERM".to_string());
        }
    }
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    LQ94721_log_event(&LogRecord {
        timestamp: now_secs,
        level: LogLevel::Info,
        module: "main".to_string(),
        message: "ablock已停止".to_string(),
        metadata: None,
    });
    Ok(())
}
fn print_banner() {
    eprintln!();
    eprintln!("  █████╗ ███████╗ ██████╗██╗  ██╗");
    eprintln!(" ██╔══██╗╚══███╔╝██╔════╝██║  ██║   ablock v0.1.0");
    eprintln!(" ███████║  ███╔╝ ██║     ███████║   容器逃逸检测与阻断系统");
    eprintln!(" ██╔══██║ ███╔╝  ██║     ██╔══██║   基于eBPF的实时安全监控");
    eprintln!(" ██║  ██║███████╗╚██████╗██║  ██║");
    eprintln!(" ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝");
    eprintln!();
}
fn init_tracing(verbose: bool) {
    let filter_level = if verbose { "debug" } else { "info" };
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter_level));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_file(false)
        .with_line_number(false)
        .init();
}
fn handle_shutdown(signal_name: String) {
    eprintln!("\n收到 {}，正在优雅退出...", signal_name);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    LQ94721_log_event(&LogRecord {
        timestamp: now_secs,
        level: LogLevel::Info,
        module: "main".to_string(),
        message: format!("收到{}，开始优雅退出", signal_name),
        metadata: None,
    });
    eprintln!("ablock已安全退出");
}
fn check_ebpf_available() -> bool {
    let ebpf_path = option_env!("ABLOCK_EBPF_PATH")
        .unwrap_or("ebpf/target/bpfel-unknown-none/release/ablock");
    std::path::Path::new(ebpf_path).exists()
}
fn print_status_summary() {
    let stats = crate::liqiu1::LQ11467_get_event_stats();
    eprintln!();
    eprintln!("=== 运行状态摘要 ===");
    eprintln!("  总事件数: {}", stats.total_events);
    eprintln!("  已阻断:   {}", stats.blocked);
    eprintln!("  已放行:   {}", stats.allowed);
    eprintln!("  已上报:   {}", stats.escalated);
    eprintln!("===================");
    eprintln!();
}
const _: () = {
    assert!(
        std::mem::size_of::<crate::liqiu1::AblockEvent>() == 280,
        "AblockEvent结构体大小不正确，破坏与eBPF端的兼容性"
    );
};
async fn recv_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut sig) => {
            sig.recv().await;
        }
        Err(_) => {
            std::future::pending::<()>().await;
        }
    }
}
fn print_config_detail(config: &crate::liqiu4::AblockConfig) {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║           ablock 配置详情                            ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  日志路径:     {:<37}║", config.log_path);
    println!("║  日志级别:     {:<37}║", format!("{:?}", config.log_level));
    println!("║  终端超时:     {:<37}║", format!("{}ms", config.terminal_timeout_ms));
    println!("║  紧急阈值:     {:<37}║", config.emergency_threshold);
    if let Some(ref falco) = config.falco_endpoint {
        println!("║  Falco端点:    {:<37}║", falco);
    } else {
        println!("║  Falco端点:    {:<37}║", "未配置");
    }
    if let Some(ref trivy) = config.trivy_endpoint {
        println!("║  Trivy端点:    {:<37}║", trivy);
    } else {
        println!("║  Trivy端点:    {:<37}║", "未配置");
    }
    println!("╚══════════════════════════════════════════════════════╝");
}
fn run_diagnostics(cli: &Cli) -> bool {
    eprintln!("🔧 运行自检诊断...");
    let mut all_ok = true;
    if cli.no_privilege_check {
        eprintln!("  [SKIP] 权限检查已跳过（--no-privilege-check）");
    } else if LQ34129_check_privilege() {
        eprintln!("  [ OK ] root权限检查通过");
    } else {
        eprintln!("  [FAIL] 非root用户运行，阻断功能将不可用");
        all_ok = false;
    }
    if check_ebpf_available() {
        eprintln!("  [ OK ] eBPF程序已编译");
    } else {
        eprintln!("  [WARN] eBPF程序未编译，运行时将自动跳过内核探针");
        eprintln!("         请运行: cd ebpf && cargo build --target=bpfel-unknown-none --release");
    }
    if std::path::Path::new(&cli.config).exists() {
        eprintln!("  [ OK ] 配置文件存在: {}", cli.config);
    } else {
        eprintln!("  [WARN] 配置文件不存在: {}（将使用默认配置）", cli.config);
    }
    let log_dir = "/var/log/ablock";
    if std::path::Path::new(log_dir).exists() {
        eprintln!("  [ OK ] 日志目录存在: {}", log_dir);
    } else {
        eprintln!("  [WARN] 日志目录不存在: {}（运行时将尝试创建）", log_dir);
    }
    let rules = crate::liqiu1::LQ28146_get_active_rules();
    eprintln!("  [ OK ] 已加载 {} 条规则", rules.len());
    if all_ok {
        eprintln!("  ✅ 自检通过");
    } else {
        eprintln!("  ⚠️ 自检发现问题（见上方），系统仍可运行但功能受限");
    }
    all_ok
}