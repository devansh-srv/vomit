use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct SlowEvents {
    pub duration_ms: f64,
    pub operation: String,
    pub tgid: u32,
    pub pid: u32,
    pub kernel_stack_id: i32,
    pub user_stack_id: i32,
}

#[repr(C)]
pub struct events {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub duration_ns: u64,
    pub size: u64, // payload size for I/O operations
    pub comm: [u8; 16],
    pub operation: [u8; 32],
    pub kernel_stack_id: i32,
    pub user_stack_id: i32,
}
pub struct Stats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub slowest_by_process: HashMap<String, SlowEvents>,
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
        let kernel_stack_id = event.kernel_stack_id;
        let user_stack_id = event.user_stack_id;
        self.slowest_by_process
            .entry(comm)
            .and_modify(|e| {
                if duration_ms > e.duration_ms {
                    *e = SlowEvents {
                        duration_ms,
                        operation: op.clone(),
                        tgid,
                        pid,
                        kernel_stack_id,
                        user_stack_id,
                    };
                }
            })
            .or_insert(SlowEvents {
                duration_ms,
                operation: op,
                tgid,
                pid,
                kernel_stack_id,
                user_stack_id,
            });
    }
    pub fn top_slow_processes(&self) -> Vec<(String, SlowEvents)> {
        let mut procs: Vec<_> = self
            .slowest_by_process
            .iter()
            .map(|(name, event)| (name.clone(), event.clone()))
            .collect();
        procs.sort_by(|a, b| b.1.duration_ms.partial_cmp(&a.1.duration_ms).unwrap());
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
