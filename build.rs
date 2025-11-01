use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

// const SRC: &str = "src/bpf/helloworld.bpf.c";
// const SRC: &str = "src/bpf/perf.bpf.c";
const SRC: &str = "src/bpf/monitor.bpf.c";

// fn main() {
//     let mut out =
//         PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
//     out.push("helloworld.skel.rs");
//
//     let arch = env::var("CARGO_CFG_TARGET_ARCH")
//         .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
//
//     SkeletonBuilder::new()
//         .source(SRC)
//         .clang_args([
//             OsStr::new("-I"),
//             Path::new("../../../vmlinux.h/include")
//                 .join(arch)
//                 .as_os_str(),
//         ])
//         .build_and_generate(&out)
//         .expect("bpf compilation failed");
//     println!("cargo:rerun-if-changed={}", SRC);
// }
//
fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    // out.push("helloworld.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([OsStr::new("-I"), OsStr::new("-O2"), OsStr::new("-g")])
        .build_and_generate(out.join("monitor.skel.rs"))
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
