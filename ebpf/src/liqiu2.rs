#![no_std]
#![no_main]
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
const EVENT_TYPE_MOUNT: u32 = 1;
const EVENT_TYPE_EXEC: u32 = 2;
const EVENT_TYPE_OPEN: u32 = 3;
const RULE_MOUNT_ENABLED: u32 = 0;
const RULE_EXEC_ENABLED: u32 = 1;
const RULE_OPEN_ENABLED: u32 = 2;
const RULE_EMERGENCY_MODE: u32 = 3;
const STAT_MOUNT_EVENTS: u32 = 0;
const STAT_EXEC_EVENTS: u32 = 1;
const STAT_OPEN_EVENTS: u32 = 2;
const STAT_TOTAL_EVENTS: u32 = 3;
#[repr(C)]
pub struct SyscallTracepointCommon {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub __syscall_nr: i32,
}
#[repr(C)]
pub struct SysEnterMountArgs {
    pub common: SyscallTracepointCommon,
    pub dev_name: u64,
    pub dir_name: u64,
    pub type_: u64,
    pub flags: u64,
    pub data: u64,
}
#[repr(C)]
pub struct SysEnterExecveArgs {
    pub common: SyscallTracepointCommon,
    pub filename: u64,
    pub argv: u64,
    pub envp: u64,
}
#[repr(C)]
pub struct SysEnterOpenatArgs {
    pub common: SyscallTracepointCommon,
    pub dfd: i32,
    pub _padding: i32,
    pub filename: u64,
    pub flags: i32,
    pub mode: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AblockEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub timestamp: u64,
    pub data: [u8; 256],
}
#[map]
static LQ55678_EVENTS: PerfEventArray<AblockEvent> = PerfEventArray::new(0);
#[map]
static LQ77341_PID_WHITELIST: aya_ebpf::maps::HashMap<u32, u8> = aya_ebpf::maps::HashMap::with_max_entries(1024, 0);
#[map]
static LQ88263_RULE_CONFIG: aya_ebpf::maps::Array<u32> = aya_ebpf::maps::Array::with_max_entries(16, 0);
#[map]
static LQ66120_EVENT_STATS: aya_ebpf::maps::Array<u64> = aya_ebpf::maps::Array::with_max_entries(8, 0);
pub mod probe_mount {
    use super::*;
    const SUSPICIOUS_MOUNT_TARGETS: &[&[u8]] = &[
        b"/host\0",
        b"/hostfs\0",
        b"/rootfs\0",
        b"/proc/1/root\0",
        b"/var/lib/docker\0",
        b"/etc\0",
        b"/dev\0",
        b"/sys\0",
        b"/run\0",
        b"/var/run\0",
    ];
    fn LQ88341_is_suspicious_target(buf: &[u8]) -> bool {
        for target in SUSPICIOUS_MOUNT_TARGETS {
            let target_len = target.len();
            if buf.len() >= target_len {
                let mut all_match = true;
                let mut i = 0;
                while i < target_len {
                    if buf[i] != target[i] {
                        all_match = false;
                        break;
                    }
                    i += 1;
                }
                if all_match {
                    return true;
                }
            }
        }
        false
    }
    pub fn LQ44763_handle_mount(ctx: &TracePointContext) -> Result<(), i64> {
        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        let pid = (pid_tgid >> 32) as u32;
        let uid_gid = unsafe { bpf_get_current_uid_gid() };
        let uid = (uid_gid & 0xFFFFFFFF) as u32;
        if super::LQ11947_check_pid_whitelist(pid) {
            return Ok(());
        }
        if !super::LQ77281_is_rule_enabled(RULE_MOUNT_ENABLED) {
            return Ok(());
        }
        let args = unsafe { ctx.read_at::<SysEnterMountArgs>(0) }.map_err(|_| -1)?;
        let target_ptr = args.dir_name as *mut u8;
        let mut data = [0u8; 256];
        let target_len = super::LQ55120_read_user_string(target_ptr, &mut data);
        let is_suspicious = if target_len > 0 {
            LQ88341_is_suspicious_target(&data[..target_len])
        } else {
            false
        };
        if is_suspicious {
            info!(ctx, "LQ44763: 可疑mount操作 pid={} uid={} target_len={}", pid, uid, target_len);
            let event = AblockEvent {
                event_type: EVENT_TYPE_MOUNT,
                pid,
                uid,
                timestamp: unsafe { bpf_ktime_get_ns() },
                data,
            };
            super::LQ33826_send_event(ctx, &event);
            super::LQ66190_increment_stat(STAT_MOUNT_EVENTS);
            super::LQ66190_increment_stat(STAT_TOTAL_EVENTS);
        }
        Ok(())
    }
}
pub mod probe_exec {
    use super::*;
    const SUSPICIOUS_BINARIES: &[&[u8]] = &[
        b"/bin/sh\0",
        b"/bin/bash\0",
        b"/bin/dash\0",
        b"/bin/nc\0",
        b"/usr/bin/nc\0",
        b"/bin/busybox\0",
        b"/usr/bin/wget\0",
        b"/usr/bin/curl\0",
        b"/tmp/\0",
        b"/dev/shm/\0",
        b"/var/tmp/\0",
    ];
    fn LQ88342_is_suspicious_binary(buf: &[u8]) -> bool {
        for binary in SUSPICIOUS_BINARIES {
            let binary_len = binary.len();
            if buf.len() >= binary_len {
                let mut all_match = true;
                let mut i = 0;
                while i < binary_len {
                    if buf[i] != binary[i] {
                        all_match = false;
                        break;
                    }
                    i += 1;
                }
                if all_match {
                    return true;
                }
            }
        }
        false
    }
    pub fn LQ22594_handle_execve(ctx: &TracePointContext) -> Result<(), i64> {
        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        let pid = (pid_tgid >> 32) as u32;
        let uid_gid = unsafe { bpf_get_current_uid_gid() };
        let uid = (uid_gid & 0xFFFFFFFF) as u32;
        if super::LQ11947_check_pid_whitelist(pid) {
            return Ok(());
        }
        if !super::LQ77281_is_rule_enabled(RULE_EXEC_ENABLED) {
            return Ok(());
        }
        let args = unsafe { ctx.read_at::<SysEnterExecveArgs>(0) }.map_err(|_| -1)?;
        let filename_ptr = args.filename as *mut u8;
        let mut data = [0u8; 256];
        let filename_len = super::LQ55120_read_user_string(filename_ptr, &mut data);
        let is_suspicious = if filename_len > 0 {
            LQ88342_is_suspicious_binary(&data[..filename_len])
        } else {
            false
        };
        if is_suspicious {
            info!(ctx, "LQ22594: 可疑execve操作 pid={} uid={} file_len={}", pid, uid, filename_len);
            let event = AblockEvent {
                event_type: EVENT_TYPE_EXEC,
                pid,
                uid,
                timestamp: unsafe { bpf_ktime_get_ns() },
                data,
            };
            super::LQ33826_send_event(ctx, &event);
            super::LQ66190_increment_stat(STAT_EXEC_EVENTS);
            super::LQ66190_increment_stat(STAT_TOTAL_EVENTS);
        }
        Ok(())
    }
}
pub mod probe_open {
    use super::*;
    const SENSITIVE_PATHS: &[&[u8]] = &[
        b"/etc/shadow\0",
        b"/etc/passwd\0",
        b"/proc/1/root\0",
        b"/proc/sys\0",
        b"/sys/kernel\0",
        b"/dev/mem\0",
        b"/dev/kmem\0",
        b"/root/.ssh\0",
        b"/var/run/docker.sock\0",
        b"/etc/kubernetes\0",
        b"/run/secrets\0",
        b"/var/run/secrets\0",
    ];
    fn LQ88343_is_sensitive_path(buf: &[u8]) -> bool {
        for path in SENSITIVE_PATHS {
            let path_len = path.len();
            if buf.len() >= path_len {
                let mut all_match = true;
                let mut i = 0;
                while i < path_len {
                    if buf[i] != path[i] {
                        all_match = false;
                        break;
                    }
                    i += 1;
                }
                if all_match {
                    return true;
                }
            }
        }
        false
    }
    pub fn LQ77841_handle_openat(ctx: &TracePointContext) -> Result<(), i64> {
        let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
        let pid = (pid_tgid >> 32) as u32;
        let uid_gid = unsafe { bpf_get_current_uid_gid() };
        let uid = (uid_gid & 0xFFFFFFFF) as u32;
        if super::LQ11947_check_pid_whitelist(pid) {
            return Ok(());
        }
        if !super::LQ77281_is_rule_enabled(RULE_OPEN_ENABLED) {
            return Ok(());
        }
        let args = unsafe { ctx.read_at::<SysEnterOpenatArgs>(0) }.map_err(|_| -1)?;
        let filename_ptr = args.filename as *mut u8;
        let mut data = [0u8; 256];
        let path_len = super::LQ55120_read_user_string(filename_ptr, &mut data);
        let is_sensitive = if path_len > 0 {
            LQ88343_is_sensitive_path(&data[..path_len])
        } else {
            false
        };
        if is_sensitive {
            info!(ctx, "LQ77841: 敏感文件访问 pid={} uid={} path_len={}", pid, uid, path_len);
            let event = AblockEvent {
                event_type: EVENT_TYPE_OPEN,
                pid,
                uid,
                timestamp: unsafe { bpf_ktime_get_ns() },
                data,
            };
            super::LQ33826_send_event(ctx, &event);
            super::LQ66190_increment_stat(STAT_OPEN_EVENTS);
            super::LQ66190_increment_stat(STAT_TOTAL_EVENTS);
        }
        Ok(())
    }
}
pub fn LQ11947_check_pid_whitelist(pid: u32) -> bool {
    unsafe { LQ77341_PID_WHITELIST.get(&pid).is_some() }
}
pub fn LQ33826_send_event(ctx: &TracePointContext, event: &AblockEvent) {
    LQ55678_EVENTS.output(ctx, event, 0);
}
pub fn LQ77281_is_rule_enabled(rule_index: u32) -> bool {
    if let Some(val) = LQ88263_RULE_CONFIG.get(rule_index) {
        *val != 0
    } else {
        false
    }
}
pub fn LQ55112_is_emergency_mode() -> bool {
    LQ77281_is_rule_enabled(RULE_EMERGENCY_MODE)
}
pub fn LQ66190_increment_stat(index: u32) {
    if let Some(ptr) = LQ66120_EVENT_STATS.get_ptr_mut(index) {
        unsafe {
            *ptr = (*ptr).wrapping_add(1);
        }
    }
}
pub fn LQ55120_read_user_string(ptr: *mut u8, buf: &mut [u8; 256]) -> usize {
    let mut len = 0;
    while len < 255 {
        let mut byte: [u8; 1] = [0];
        let ret = unsafe {
            bpf_probe_read_user(
                byte.as_mut_ptr(),
                1,
                ptr.add(len),
            )
        };
        if ret < 0 {
            break;
        }
        if byte[0] == 0 {
            break;
        }
        buf[len] = byte[0];
        len += 1;
    }
    len
}
extern "C" {
    fn bpf_get_current_pid_tgid() -> u64;
    fn bpf_get_current_uid_gid() -> u64;
    fn bpf_ktime_get_ns() -> u64;
    fn bpf_probe_read_user(dst: *mut u8, size: u32, src: *const u8) -> i64;
}
#[tracepoint]
pub fn LQ99421_trace_mount(ctx: TracePointContext) -> u32 {
    match probe_mount::LQ44763_handle_mount(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
#[tracepoint]
pub fn LQ66182_trace_execve(ctx: TracePointContext) -> u32 {
    match probe_exec::LQ22594_handle_execve(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
#[tracepoint]
pub fn LQ55307_trace_openat(ctx: TracePointContext) -> u32 {
    match probe_open::LQ77841_handle_openat(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
#[tracepoint]
pub fn LQ99812_tracepoint_sched(ctx: TracePointContext) -> u32 {
    let _ = ctx;
    0
}
#[panic_handler]
fn LQ44219_panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}