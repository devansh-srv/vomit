use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::{mem::MaybeUninit, time::Duration};

include!(concat!(env!("OUT_DIR"), "/helloworld.skel.rs"));
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut skel_builder = HelloworldSkelBuilder::default();
    let mut open_skel = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_skel)?;

    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!(
        "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs."
    );
    println!("Press Ctrl-C to stop.");

    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
