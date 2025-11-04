// use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
// use std::{mem::MaybeUninit, time::Duration};
// mod collector;
// include!(concat!(env!("OUT_DIR"), "/helloworld.skel.rs"));
// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let mut skel_builder = HelloworldSkelBuilder::default();
//     let mut open_skel = MaybeUninit::uninit();
//     let open_skel = skel_builder.open(&mut open_skel)?;
//
//     let mut skel = open_skel.load()?;
//     skel.attach()?;
//
//     println!(
//         "Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs."
//     );
//     println!("Press Ctrl-C to stop.");
//
//     loop {
//         std::thread::sleep(Duration::from_secs(1));
//     }
// }
mod collector;
mod strace;
mod tui;
use anyhow::Result;
use collector::{SharedStats, Stats};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/monitor.skel.rs"));
fn main() -> Result<()> {
    println!("PerfLens - Starting eBPF monitoring...");
    let mut skel_builder = MonitorSkelBuilder::default();
    let mut open_skel = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_skel)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!(" BPF programs loaded and attached");
    println!(" Monitoring slow operations (>5ms)");
    println!(" Tracking: read, write, disk I/O\n");
    let stats: SharedStats = Arc::new(Mutex::new(Stats::new()));
    let stats_clone = Arc::clone(&stats);

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder
        .add(&skel.maps.events, move |data| {
            collector::handle_events(data, &stats_clone)
        })
        .expect("Failed to add ring buffer");
    let ringbuf = rb_builder.build().expect("Failed to build ring buffer");
    let collector_handle = thread::spawn(move || {
        println!("Event collector thread started");
        loop {
            if let Err(e) = ringbuf.poll(Duration::from_millis(100)) {
                eprintln!("Ring buffer poll error: {}", e);
                break;
            }
        }
        println!("Event collector thread stopped");
    });
    let stack_map = skel.maps.stack_traces;
    tui::run_tui(stats, &stack_map)?;
    // collector_handle.join().unwrap();
    Ok(())
}
