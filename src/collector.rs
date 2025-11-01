use anyhow::Result;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

#[repr(C)]
pub struct events {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub duration_ns: u64,
    pub size: u64, // payload size for I/O operations
    pub comm: [u8; 16],
    pub operation: [u8; 32],
}
pub struct Stats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub slowest_by_process: HashMap<String, (f64, String, u32, u32)>,
}
impl Stats {
    pub fn new() -> Self {
        Self {
            total_events: 0,
            events_by_type: HashMap::new(),
            slowest_by_process: HashMap::new(),
        }
    }
    pub fn add_event(&mut self, event: &events) {
        self.total_events += 1;
        let op = String::from_utf8_lossy(&event.operation)
            .trim_end_matches("\0")
            .to_string();
        *self.events_by_type.entry(op.clone()).or_insert(0) += 1;
        let comm = String::from_utf8_lossy(&event.comm)
            .trim_end_matches("\0")
            .to_string();
        let duration_ms = event.duration_ns as f64 / 1_000_000.0;
        let tgid = event.tgid as u32;
        let pid = event.pid as u32;
        self.slowest_by_process
            .entry(comm)
            .and_modify(|(max, _, _, _)| {
                if duration_ms > *max {
                    *max = duration_ms;
                }
            })
            .or_insert((duration_ms, op, tgid, pid));
    }
    pub fn top_slow_processes(&self) -> Vec<(String, f64, String, u32, u32)> {
        let mut procs: Vec<_> = self
            .slowest_by_process
            .iter()
            .map(|(name, (ms, op, tgid, pid))| (name.clone(), *ms, op.clone(), *tgid, *pid))
            .collect();
        procs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        procs.truncate(10);
        procs
    }
}

pub type SharedStats = Arc<Mutex<Stats>>;
pub fn handle_events(data: &[u8], stats: &SharedStats) -> i32 {
    if data.len() != std::mem::size_of::<events>() {
        return 0;
    }

    let event = unsafe { &*(data.as_ptr() as *const events) };

    let mut stats = stats.lock().unwrap();
    stats.add_event(event);

    0
}
