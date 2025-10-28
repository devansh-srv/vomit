use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

// const SRC: &str = "src/bpf/helloworld.bpf.c";
const SRC: &str = "src/bpf/perf.bpf.c";

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
fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));

    // let arch = env::var("CARGO_CFG_TARGET_ARCH")
    //     .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    // SkeletonBuilder::new()
    //     .source(SRC)
    //     .clang_args([
    //         OsStr::new("-I"),
    //         OsStr::new("src/bpf"),
    //         OsStr::new("-g"),
    //         Path::new("../../../vmlinux.h/include")
    //             .join(arch)
    //             .as_os_str(),
    //     ])
    //     .build_and_generate(out.join("perf.skel.rs"))
    //     .expect("bpf compilation failed");
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(&["-I", "src/bpf", "-g"])
        .build_and_generate(out.join("perf.skel.rs"))
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");
}
