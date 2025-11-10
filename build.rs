use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/monitor.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([OsStr::new("-I"), OsStr::new("-O2"), OsStr::new("-g")])
        .build_and_generate(out.join("monitor.skel.rs"))
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
