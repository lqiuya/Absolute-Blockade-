use std::{env, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ebpf_dir = dir.join("ebpf");

    let status = std::process::Command::new("cargo")
        .arg("+nightly")
        .arg("build")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core")
        .arg("--release")
        .current_dir(&ebpf_dir)
        .status();

    match status {
        Ok(s) if s.success() => {
            let ebpf_elf = ebpf_dir.join("target/bpfel-unknown-none/release/ablock");
            println!("cargo:rustc-env=ABLOCK_EBPF_PATH={}", ebpf_elf.display());
        }
        _ => {
            println!("cargo:warning=eBPF编译被跳过（bpfel-unknown-none目标可能未安装）");
            println!("cargo:warning=运行时需要先手动编译eBPF：cd ebpf && cargo build --target=bpfel-unknown-none --release");
            let ebpf_elf = ebpf_dir.join("target/bpfel-unknown-none/release/ablock");
            println!("cargo:rustc-env=ABLOCK_EBPF_PATH={}", ebpf_elf.display());
        }
    }

    println!("cargo:rerun-if-changed=ebpf/src/liqiu2.rs");
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
}