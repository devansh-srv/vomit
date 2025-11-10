use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

const TIMELINE_WINDOW_SECS: u64 = 300; // Keep 5 minutes
const BUCKET_SIZE_MS: u64 = 1000; // 1-second buckets

#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub tgid: u32,
    pub pid: u32,
    pub details: EventDetails,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventType {
    SlowOp,
    ProcessFork,
    ProcessExec,
}

#[derive(Debug, Clone)]
pub enum EventDetails {
    SlowOp {
        operation: String,
        duration_ms: f64,
        comm: String,
    },
    Fork {
        parent_comm: String,
        child_comm: String,
        parent_tgid: u32,
        child_tgid: u32,
    },
    Exec {
        comm: String,
        filename: String,
    },
}

pub struct Timeline {
    pub events: VecDeque<TimelineEvent>,
    pub buckets: HashMap<u64, BucketStats>,
    pub process_tree: HashMap<u32, ProcessNode>,
    max_events: usize,
}

#[derive(Debug, Clone, Default)]
pub struct BucketStats {
    pub slow_ops: u32,
    pub forks: u32,
    pub execs: u32,
    pub total_duration_ms: f64,
}

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub tgid: u32,
    pub comm: String,
    pub parent_tgid: Option<u32>,
    pub children: Vec<u32>,
    pub first_seen: u64,
    pub slow_events: u32,
}

impl Timeline {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            buckets: HashMap::new(),
            process_tree: HashMap::new(),
            max_events: 10000,
        }
    }

    pub fn add_event(&mut self, event: TimelineEvent) {
        let bucket = self.get_bucket(event.timestamp_ns);

        // Update bucket stats
        let stats = self.buckets.entry(bucket).or_insert_with(Default::default);
        match &event.event_type {
            EventType::SlowOp => {
                stats.slow_ops += 1;
                if let EventDetails::SlowOp { duration_ms, .. } = &event.details {
                    stats.total_duration_ms += duration_ms;
                }
            }
            EventType::ProcessFork => stats.forks += 1,
            EventType::ProcessExec => stats.execs += 1,
        }

        // Update process tree
        self.update_process_tree(&event);

        // Add to timeline
        self.events.push_back(event);

        // Trim old events
        if self.events.len() > self.max_events {
            self.events.pop_front();
        }

        // Cleanup old buckets
        self.cleanup_old_buckets();
    }

    fn get_bucket(&self, timestamp_ns: u64) -> u64 {
        let timestamp_ms = timestamp_ns / 1_000_000;
        (timestamp_ms / BUCKET_SIZE_MS) * BUCKET_SIZE_MS
    }

    fn update_process_tree(&mut self, event: &TimelineEvent) {
        match &event.details {
            EventDetails::Fork {
                parent_comm,
                child_comm,
                parent_tgid,
                child_tgid,
            } => {
                // Update parent
                self.process_tree
                    .entry(*parent_tgid)
                    .and_modify(|node| {
                        if !node.children.contains(child_tgid) {
                            node.children.push(*child_tgid);
                        }
                    })
                    .or_insert_with(|| ProcessNode {
                        tgid: *parent_tgid,
                        comm: parent_comm.clone(),
                        parent_tgid: None,
                        children: vec![*child_tgid],
                        first_seen: event.timestamp_ns,
                        slow_events: 0,
                    });

                // Create child
                self.process_tree
                    .entry(*child_tgid)
                    .or_insert_with(|| ProcessNode {
                        tgid: *child_tgid,
                        comm: child_comm.clone(),
                        parent_tgid: Some(*parent_tgid),
                        children: Vec::new(),
                        first_seen: event.timestamp_ns,
                        slow_events: 0,
                    });
            }
            EventDetails::Exec { comm, .. } => {
                // Update comm if process exists
                if let Some(node) = self.process_tree.get_mut(&event.tgid) {
                    node.comm = comm.clone();
                }
            }
            EventDetails::SlowOp { comm, .. } => {
                self.process_tree
                    .entry(event.tgid)
                    .and_modify(|node| node.slow_events += 1)
                    .or_insert_with(|| ProcessNode {
                        tgid: event.tgid,
                        comm: comm.clone(),
                        parent_tgid: None,
                        children: Vec::new(),
                        first_seen: event.timestamp_ns,
                        slow_events: 1,
                    });
            }
        }
    }

    fn cleanup_old_buckets(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let cutoff = now.saturating_sub(TIMELINE_WINDOW_SECS * 1000);
        self.buckets.retain(|&bucket, _| bucket >= cutoff);
    }

    pub fn get_recent_buckets(&self, count: usize) -> Vec<(u64, BucketStats)> {
        let mut buckets: Vec<_> = self
            .buckets
            .iter()
            .map(|(ts, stats)| (*ts, stats.clone()))
            .collect();
        buckets.sort_by_key(|(ts, _)| *ts);
        buckets.into_iter().rev().take(count).collect()
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<&TimelineEvent> {
        self.events.iter().rev().take(count).collect()
    }
}
