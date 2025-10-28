// use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
// use std::{mem::MaybeUninit, time::Duration};
//
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
//
use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{PerfBufferBuilder, RingBufferBuilder};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/perf.skel.rs"));

#[repr(C)]
#[derive(Debug, Clone)]
struct SyscallPerf {
    pid: u32,
    tid: u32,
    comm: [u8; 16],
    syscall_id: u64,
    duration_ns: u64,
    timestamp: u64,
}
#[repr(C)]
#[derive(Debug, Clone)]
struct IoPerf {
    pid: u32,
    comm: [u8; 16],
    bytes: u64,
    latency_ns: u64,
    timestamp: u64,
    operation: u8,
}
#[repr(C)]
#[derive(Debug, Clone)]
struct CpuSample {
    pid: u32,
    comm: [u8; 16],
    cpu_id: u32,
    timestamp: u64,
}

struct PerfStats {
    syscall_cnt: HashMap<u64, u32>,
    slow_syscalls: Vec<SyscallPerf>,
    slow_ios: Vec<IoPerf>,
    cpu_samples: HashMap<String, u32>,
}

impl PerfStats {
    fn new() -> Self {
        Self {
            syscall_cnt: HashMap::new(),
            slow_syscalls: Vec::new(),
            slow_ios: Vec::new(),
            cpu_samples: HashMap::new(),
        }
    }

    fn add_syscall(&mut self, event: SyscallPerf) {
        *self.syscall_cnt.entry(event.syscall_id).or_insert(0) += 1;
        self.slow_syscalls.push(event);
    }
    fn add_io(&mut self, event: IoPerf) {
        self.slow_ios.push(event);
    }
    fn add_cpu_sample(&mut self, event: CpuSample) {
        let comm = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();
        *self.cpu_samples.entry(comm).or_insert(0) += 1;
    }
    fn summary(&self) -> String {
        format!(
            "Performance Summary:\n\
             - Total slow syscalls: {}\n\
             - Total slow I/O operations: {}\n\
             - CPU samples collected: {}\n\
             - Top CPU consumer: {:?}",
            self.slow_syscalls.len(),
            self.slow_ios.len(),
            self.cpu_samples.values().sum::<u32>(),
            self.cpu_samples
                .iter()
                .max_by_key(|(_, count)| *count)
                .map(|(name, count)| format!("{}: {}", name, count))
        )
    }
}

fn handle_event(data: &[u8], stats: &mut PerfStats) -> Result<()> {
    match data.len() {
        size if size == std::mem::size_of::<SyscallPerf>() => {
            let event = unsafe { std::ptr::read(data.as_ptr() as *const SyscallPerf) };
            let comm = String::from_utf8_lossy(&event.comm);
            println!(
                "[SYSCALL] PID {} ({}) - syscall {} took {:.2}ms",
                event.pid,
                comm.trim_end_matches('\0'),
                event.syscall_id,
                event.duration_ns as f64 / 1_000_000.0
            );
            stats.add_syscall(event);
        }
        size if size == std::mem::size_of::<IoPerf>() => {
            let event = unsafe { std::ptr::read(data.as_ptr() as *const IoPerf) };
            let comm = String::from_utf8_lossy(&event.comm);
            let op = if event.operation == 0 {
                "READ"
            } else {
                "WRITE"
            };
            println!(
                "[I/O] PID {} ({}) - {} {} bytes, latency: {:.2}ms",
                event.pid,
                comm.trim_end_matches('\0'),
                op,
                event.bytes,
                event.latency_ns as f64 / 1_000_000.0
            );
            stats.add_io(event);
        }
        size if size == std::mem::size_of::<CpuSample>() => {
            let sample = unsafe { std::ptr::read(data.as_ptr() as *const CpuSample) };
            stats.add_cpu_sample(sample);
        }
        _ => {
            eprint!("Unknown Event with size: {}", data.len())
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut skel_builder = PerfSkelBuilder::default();
    let mut open_skel = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_skel)?;
    // let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    println!("Performance monitoring started!");
    println!("Tracking: syscalls, disk I/O, CPU usage");
    println!("Press Ctrl-C to stop and see summary\n");
    let mut stats = PerfStats::new();

    let mut builder = RingBufferBuilder::new();
    builder.add(&skel.maps.events, move |data| {
        handle_event(data, &mut stats)
            .unwrap_or_else(|e| eprintln!("Error handling the event: {}", e));
        0
    })?;
    let ringbuf = builder.build()?;
    loop {
        ringbuf.poll(Duration::from_millis(100))?; //10 seconds polling
    }
}
