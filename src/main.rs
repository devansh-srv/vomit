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
mod tui;
use anyhow::Result;
use collector::{SharedStats, Stats};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libc::exit;
use serde::de::Expected;
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
        loop {
            ringbuf
                .poll(Duration::from_millis(100))
                .expect("Failed to poll ring buffer");
        }
    });
    tui::run_tui(stats)?;
    collector_handle.join().unwrap();
    Ok(())
}
