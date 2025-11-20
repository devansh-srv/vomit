use crate::collector::Stats;
use crate::timeline::EventType;

pub fn create_analysis_prompt(stats: &Stats) -> String {
    let mut prompt = String::from(
        "You are a Linux performance analysis expert. Analyze this system performance data and provide:\n\
        1. Summary of performance issues\n\
        2. Root cause analysis\n\
        3. Specific recommendations\n\n\
        System Performance Data:\n\n",
    );

    // Overall stats
    prompt.push_str(&format!(
        "Total slow operations (>5ms): {}\n",
        stats.total_events
    ));

    // By operation type
    prompt.push_str("\nOperations breakdown:\n");
    for (op, count) in &stats.events_by_type {
        prompt.push_str(&format!("  - {}: {} operations\n", op, count));
    }

    // Slowest processes
    prompt.push_str("\nSlowest processes:\n");
    let top_procs = stats.top_slow_processes();
    for (name, event) in top_procs.iter().take(5) {
        prompt.push_str(&format!(
            "  - {} (PID {}): {:.2}ms during {} operation\n",
            name, event.tgid, event.duration_ms, event.operation
        ));
    }

    // Recent timeline events
    prompt.push_str("\nRecent activity:\n");
    let recent_events = stats.timeline.get_recent_events(10);
    for event in recent_events {
        match &event.details {
            crate::timeline::EventDetails::SlowOp {
                operation,
                duration_ms,
                comm,
            } => {
                prompt.push_str(&format!(
                    "  - {} slow {} operation: {:.2}ms\n",
                    comm, operation, duration_ms
                ));
            }
            crate::timeline::EventDetails::Fork {
                parent_comm,
                child_comm,
                ..
            } => {
                prompt.push_str(&format!(
                    "  - Process fork: {} → {}\n",
                    parent_comm, child_comm
                ));
            }
            crate::timeline::EventDetails::Exec { comm, filename } => {
                prompt.push_str(&format!(
                    "  - Process exec: {} running {}\n",
                    comm, filename
                ));
            }
        }
    }

    // Process tree context
    let process_count = stats.timeline.process_tree.len();
    let processes_with_issues: usize = stats
        .timeline
        .process_tree
        .values()
        .filter(|n| n.slow_events > 0)
        .count();

    prompt.push_str(&format!(
        "\nProcess context: {} total processes tracked, {} with performance issues\n",
        process_count, processes_with_issues
    ));

    // Event distribution
    let buckets = stats.timeline.get_recent_buckets(10);
    if !buckets.is_empty() {
        prompt.push_str("\nRecent event rate (last 10 seconds):\n");
        for (_, bucket) in buckets.iter().take(5) {
            prompt.push_str(&format!(
                "  - {} slow ops, {} forks, {} execs (avg latency: {:.2}ms)\n",
                bucket.slow_ops,
                bucket.forks,
                bucket.execs,
                if bucket.slow_ops > 0 {
                    bucket.total_duration_ms / bucket.slow_ops as f64
                } else {
                    0.0
                }
            ));
        }
    }

    prompt.push_str("\nProvide analysis:\n");

    prompt
}
