use crate::collector;
use crate::timeline::{EventDetails, EventType, Timeline, TimelineEvent};
use std::array::from_ref;
use std::collections::HashMap;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};
const EVENT_TYPE_SLOW_OP: u8 = 1;
const EVENT_TYPE_FORK: u8 = 2;
const EVENT_TYPE_EXEC: u8 = 3;

#[repr(C)]
#[derive(Debug)]
pub struct Header {
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub event_type: u8,
}

#[repr(C)]
pub struct SlowOpEvent {
    header: Header,
    duration_ns: u64,
    size: u64, //payload for I/O operations
    comm: [u8; 16],
    operation: [u8; 32],
    kernel_stack_id: i32,
    user_stack_id: i32,
}

#[repr(C)]
pub struct ForkEvent {
    header: Header,
    parent_comm: [u8; 16],
    child_comm: [u8; 16],
    parent_tgid: u32,
    child_tgid: u32,
}

#[repr(C)]
pub struct ExecEvent {
    header: Header,
    comm: [u8; 16],
    filename: [u8; 64],
}

#[derive(Debug, Clone)]
pub struct SlowEvents {
    pub duration_ms: f64,
    pub operation: String,
    pub tgid: u32,
    pub pid: u32,
    pub kernel_stack_id: i32,
    pub user_stack_id: i32,
}

pub struct Stats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub slowest_by_process: HashMap<String, SlowEvents>,
    pub timeline: Timeline,
}
impl Stats {
    pub fn new() -> Self {
        Self {
            total_events: 0,
            events_by_type: HashMap::new(),
            slowest_by_process: HashMap::new(),
            timeline: Timeline::new(),
        }
    }
    fn handle_slow_op(&mut self, event: &SlowOpEvent) {
        self.total_events += 1;
        let operation = String::from_utf8_lossy(&event.operation)
            .trim_end_matches('\0')
            .to_string();
        *self.events_by_type.entry(operation.clone()).or_insert(0) += 1;
        let comm = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();
        let duration_ms = event.duration_ns as f64 / 1_000_000.0;
        self.slowest_by_process
            .entry(comm.clone())
            .and_modify(|e| {
                if duration_ms > e.duration_ms {
                    *e = SlowEvents {
                        duration_ms,
                        operation: operation.clone(),
                        tgid: event.header.tgid,
                        pid: event.header.pid,
                        kernel_stack_id: e.kernel_stack_id,
                        user_stack_id: e.user_stack_id,
                    };
                }
            })
            .or_insert(SlowEvents {
                duration_ms,
                operation: operation.clone(),
                tgid: event.header.tgid,
                pid: event.header.pid,
                user_stack_id: event.user_stack_id,
                kernel_stack_id: event.kernel_stack_id,
            });
        self.timeline.add_event(TimelineEvent {
            timestamp_ns: event.header.timestamp_ns,
            event_type: EventType::SlowOp,
            tgid: event.header.tgid,
            pid: event.header.pid,
            details: EventDetails::SlowOp {
                operation,
                duration_ms,
                comm,
            },
        });
    }
    fn handle_fork(&mut self, event: &ForkEvent) {
        // self.total_events+=1;
        let parent_comm = String::from_utf8_lossy(&event.parent_comm)
            .trim_end_matches('\0')
            .to_string();
        let child_comm = String::from_utf8_lossy(&event.child_comm)
            .trim_end_matches('\0')
            .to_string();
        self.timeline.add_event(TimelineEvent {
            timestamp_ns: event.header.timestamp_ns,
            event_type: EventType::ProcessFork,
            tgid: event.header.tgid,
            pid: event.header.pid,
            details: EventDetails::Fork {
                parent_comm,
                child_comm,
                parent_tgid: event.parent_tgid,
                child_tgid: event.child_tgid,
            },
        });
    }
    fn handle_exec(&mut self, event: &ExecEvent) {
        let comm = String::from_utf8_lossy(&event.comm)
            .trim_end_matches('\0')
            .to_string();
        let filename = String::from_utf8_lossy(&event.filename)
            .trim_end_matches('\0')
            .to_string();
        self.timeline.add_event(TimelineEvent {
            timestamp_ns: event.header.timestamp_ns,
            event_type: EventType::ProcessExec,
            tgid: event.header.tgid,
            pid: event.header.pid,
            details: EventDetails::Exec { comm, filename },
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
    if data.len() < std::mem::size_of::<Header>() {
        return 0;
    }
    let header = unsafe { &*(data.as_ptr() as *const Header) };
    let mut stats = stats.lock().unwrap();
    match header.event_type {
        EVENT_TYPE_SLOW_OP => {
            if data.len() == std::mem::size_of::<SlowOpEvent>() {
                let event = unsafe { &*(data.as_ptr() as *const SlowOpEvent) };
                stats.handle_slow_op(event);
            }
        }
        EVENT_TYPE_FORK => {
            if data.len() == std::mem::size_of::<ForkEvent>() {
                let event = unsafe { &*(data.as_ptr() as *const ForkEvent) };
                stats.handle_fork(event);
            }
        }
        EVENT_TYPE_EXEC => {
            if data.len() == std::mem::size_of::<ExecEvent>() {
                let event = unsafe { &*(data.as_ptr() as *const ExecEvent) };
                stats.handle_exec(event);
            }
        }
        _ => {}
    }

    0
}
