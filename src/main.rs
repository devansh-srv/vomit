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
mod analysis;
mod collector;
mod llm;
mod strace;
mod timeline;
mod tui;
use analysis::Analysis;
use anyhow::Result;
use collector::{SharedStats, Stats};
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use llm::LLMClient;
use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;

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
    let hf_token = std::env::var("HF_TOKEN");
    if hf_token.is_ok() {
        println!("LLM analysis enabled\n");
    } else {
        println!("HF_API_TOKEN not set - LLM analysis disabled\n");
    }
    let stats: SharedStats = Arc::new(Mutex::new(Stats::new()));
    let stats_clone = Arc::clone(&stats);
    let analyses = Arc::new(Mutex::new(Vec::new()));

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder
        .add(&skel.maps.events, move |data| {
            collector::handle_events(data, &stats_clone)
        })
        .expect("Failed to add ring buffer");
    let ringbuf = rb_builder.build().expect("Failed to build ring buffer");
    let _collector_handle = thread::spawn(move || {
        println!("Event collector thread started");
        loop {
            if let Err(e) = ringbuf.poll(Duration::from_millis(100)) {
                eprintln!("Ring buffer poll error: {}", e);
                break;
            }
        }
        println!("Event collector thread stopped");
    });
    if let Ok(token) = hf_token {
        let stats_clone = Arc::clone(&stats);
        let analyses_clone = Arc::clone(&analyses);

        thread::spawn(move || {
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let client = LLMClient::new(token);
                println!("LLM analyzer thread started");

                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;

                    // Get current stats
                    let stats_snapshot = {
                        let stats = stats_clone.lock().unwrap();
                        if stats.total_events == 0 {
                            continue;
                        }

                        // Create prompt
                        llm::create_analysis_prompt(&stats)
                    };

                    println!("Requesting LLM analysis...");

                    match client.analyze(stats_snapshot).await {
                        Ok(analysis_text) => {
                            let analysis = Analysis::new(analysis_text);
                            println!("Analysis received");

                            let mut analyses = analyses_clone.lock().unwrap();
                            analyses.push(analysis);

                            // Keep only last 10
                            if analyses.len() > 10 {
                                analyses.remove(0);
                            }
                        }
                        Err(e) => {
                            eprintln!("LLM analysis failed: {}", e);
                        }
                    }
                }
            });
        });
    }
    let stack_map = skel.maps.stack_traces;
    tui::run_tui(stats, analyses, &stack_map)?;
    Ok(())
}
