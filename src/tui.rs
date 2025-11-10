use crate::collector::{SharedStats, SlowEvents, Stats};
use crate::strace::{StackResolver, read_stack_from_map};
use crate::timeline::{EventDetails, EventType, ProcessNode};
use anyhow::Result;
use crossterm::event::ModifierKeyCode;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use libbpf_rs::Map;
use ratatui::prelude::BlockExt;
use ratatui::style::Styled;
use ratatui::widgets::BorderType;
use ratatui::widgets::Sparkline;
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use std::io;
use std::time::Duration;

enum View {
    Dashboard,
    StackTrace,
    Timeline,
    ProcessTree,
}

pub struct TuiState {
    view: View,
    selected_procs: Option<(String, SlowEvents)>,
    scroll: u16,
}
impl TuiState {
    fn new() -> Self {
        Self {
            view: View::Dashboard,
            selected_procs: None,
            scroll: 0,
        }
    }
}

fn format_timestamp(timestamp_ns: u64) -> String {
    let secs = timestamp_ns / 1_000_000_000;
    let millis = (timestamp_ns % 1_000_000_000) / 1_000_000;
    format!("{}.{:03}", secs, millis)
}
pub fn run_tui(stats: SharedStats, stack_map: &Map) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = TuiState::new();
    let mut resolver = StackResolver::new()?;
    loop {
        terminal.draw(|f| match state.view {
            View::StackTrace => render_stack_trace(f, &mut state, stack_map, &mut resolver),
            View::Dashboard => render_dashboard(f, &stats, &mut state),
            View::Timeline => render_timeline(f, &stats, &mut state),
            View::ProcessTree => render_process_tree(f, &stats, &mut state),
        })?;
        if event::poll(Duration::from_millis(100))? {
            if let Ok(Event::Key(key)) = event::read() {
                match key.code {
                    KeyCode::Char('q') => {
                        if matches!(state.view, View::StackTrace) {
                            state.view = View::Dashboard;
                        } else {
                            break;
                        }
                    }
                    KeyCode::Char('s') | KeyCode::Enter => {
                        if matches!(state.view, View::Dashboard) {
                            let stats_lock = stats.lock().unwrap();
                            if let Some((name, event)) = stats_lock.top_slow_processes().first() {
                                state.selected_procs = Some((name.clone(), event.clone()));
                                state.view = View::StackTrace;
                                state.scroll = 0;
                            }
                        }
                    }
                    KeyCode::Down => {
                        state.scroll = state.scroll.saturating_add(1);
                    }
                    KeyCode::Up => {
                        state.scroll = state.scroll.saturating_sub(1);
                    }
                    KeyCode::Char('t') => {
                        state.view = View::Timeline;
                        state.scroll = 0;
                    }
                    KeyCode::Char('p') => {
                        state.view = View::ProcessTree;
                        state.scroll = 0;
                    }
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
fn render_dashboard(f: &mut Frame, stats: &SharedStats, state: &mut TuiState) {
    let stats = stats.lock().unwrap();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());
    //header
    let header = Paragraph::new(
        "PerfLens - eBPF Performance Monitor | 'q' quit |'s' stack trace | Enter: details",
    )
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, layout[0]);

    //main component
    let main_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    //left:summary
    let summary_text = vec![
        Line::from(vec![
            Span::raw("Total Slow operations: "),
            Span::styled(
                format!("{}", stats.total_events),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "By Type:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    let mut type_lines: Vec<Line> = stats
        .events_by_type
        .iter()
        .map(|(op, count)| Line::from(format!(" {}: {}", op, count)))
        .collect();
    let mut all_lines = summary_text;
    all_lines.append(&mut type_lines);
    let summary =
        Paragraph::new(all_lines).block(Block::default().title("Summary").borders(Borders::ALL));
    f.render_widget(summary, main_layout[0]);

    //right: top_slow_processes
    let items: Vec<ListItem> = stats
        .top_slow_processes()
        .iter()
        .map(|(name, event)| {
            let id_str = if event.tgid == event.pid {
                format!("PID {}", event.tgid)
            } else {
                format!("PID {} TID {}", event.tgid, event.pid)
            };
            let has_stack = event.user_stack_id >= 0 || event.kernel_stack_id >= 0;
            ListItem::new(format!(
                "{} ({}) - {:.2}ms ({})",
                name, id_str, event.duration_ms, event.operation
            ))
        })
        .collect();
    let list = List::new(items)
        .block(
            Block::default()
                .title("Slowest Processes")
                .borders(Borders::ALL),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(list, main_layout[1]);
}

fn render_stack_trace(
    f: &mut Frame,
    state: &TuiState,
    stack_map: &Map,
    resolver: &mut StackResolver,
) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());
    //header
    let header = Paragraph::new("Stack Trace Viewer | 'q' back | ↑↓ scroll")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, layout[0]);

    //stack trace component
    if let Some((name, event)) = &state.selected_procs {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Process: ", Style::default().fg(Color::Yellow)),
                Span::raw(name),
            ]),
            Line::from(vec![
                Span::styled("PID: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", event.tgid)),
            ]),
            Line::from(vec![
                Span::styled("Duration: ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    format!("{:.2}ms", event.duration_ms),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Operation: ", Style::default().fg(Color::Yellow)),
                Span::raw(&event.operation),
            ]),
            Line::from(""),
        ];
        if event.kernel_stack_id >= 0 {
            lines.push(Line::from(Span::styled(
                "Kernel Stack:",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )));
            match read_stack_from_map(stack_map, event.kernel_stack_id) {
                Ok(addresses) => {
                    if !addresses.is_empty() {
                        let resolved = resolver.resolve_kernel_stack(&addresses);
                        for frame in &resolved.frames {
                            let line = if frame.offset > 0 {
                                format!(
                                    "  → {}+0x{:x} ({})",
                                    frame.symbol, frame.offset, frame.module
                                )
                            } else {
                                format!("  → {} ({})", frame.symbol, frame.module)
                            };
                            lines.push(Line::from(line));
                        }
                    } else {
                        lines.push(Line::from(Span::styled(
                            "  (no frames captured)",
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
                Err(e) => {
                    lines.push(Line::from(Span::styled(
                        format!("  Error: {}", e),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
            lines.push(Line::from(""));
        }
        if event.user_stack_id >= 0 {
            lines.push(Line::from(Span::styled(
                "User Stack:",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )));
            match read_stack_from_map(stack_map, event.user_stack_id) {
                Ok(addresses) => {
                    if !addresses.is_empty() {
                        let resolved = resolver.resolve_user_stack(event.tgid, &addresses);
                        for frame in &resolved.frames {
                            let line = if frame.offset > 0 {
                                format!(
                                    "  → {}+0x{:x} ({})",
                                    frame.symbol, frame.offset, frame.module
                                )
                            } else {
                                format!("  → {} ({})", frame.symbol, frame.module)
                            };
                            lines.push(Line::from(line));
                        }
                    } else {
                        lines.push(Line::from(Span::styled(
                            "  (no frames captured)",
                            Style::default().fg(Color::DarkGray),
                        )));
                    }
                }
                Err(e) => {
                    lines.push(Line::from(Span::styled(
                        format!("  Error: {}", e),
                        Style::default().fg(Color::Red),
                    )));
                }
            }
        }
        if event.kernel_stack_id < 0 && event.user_stack_id < 0 {
            lines.push(Line::from(Span::styled(
                "No stack trace available for this event",
                Style::default().fg(Color::DarkGray),
            )));
        }
        let paragraph = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Stack Trace Details")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false })
            .scroll((state.scroll, 0));

        f.render_widget(paragraph, layout[1]);
    }
}
fn render_timeline(f: &mut Frame, stats: &SharedStats, state: &mut TuiState) {
    let stats = stats.lock().unwrap();

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(10),
            Constraint::Min(0),
        ])
        .split(f.area());

    let header = Paragraph::new("Timeline View | 'q' back | ↑↓ scroll")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, layout[0]);

    // Histogram
    let buckets = stats.timeline.get_recent_buckets(60);
    let data: Vec<u64> = buckets
        .iter()
        .map(|(_, bucket_stats)| bucket_stats.slow_ops as u64)
        .collect();

    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title("Events per Second (last 60s)")
                .borders(Borders::ALL),
        )
        .data(&data)
        .style(Style::default().fg(Color::Yellow))
        .max(data.iter().max().copied().unwrap_or(1));

    f.render_widget(sparkline, layout[1]);

    // Recent events
    let recent_events = stats.timeline.get_recent_events(100);
    let items: Vec<ListItem> = recent_events
        .iter()
        .map(|event| {
            let time = format_timestamp(event.timestamp_ns);
            let line = match &event.details {
                EventDetails::SlowOp {
                    operation,
                    duration_ms,
                    comm,
                } => {
                    format!(
                        "[{}] {} (PID {}) - {} {:.2}ms",
                        time, comm, event.tgid, operation, duration_ms
                    )
                }
                EventDetails::Fork {
                    parent_comm,
                    child_comm,
                    parent_tgid,
                    child_tgid,
                } => {
                    format!(
                        "[{}] FORK: {} (PID {}) → {} (PID {})",
                        time, parent_comm, parent_tgid, child_comm, child_tgid
                    )
                }
                EventDetails::Exec { comm, filename } => {
                    format!(
                        "[{}] EXEC: {} (PID {}) executing {}",
                        time, comm, event.tgid, filename
                    )
                }
            };

            let color = match event.event_type {
                EventType::SlowOp => Color::Yellow,
                EventType::ProcessFork => Color::Green,
                EventType::ProcessExec => Color::Cyan,
            };

            ListItem::new(line).style(Style::default().fg(color))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title("Recent Events")
            .borders(Borders::ALL),
    );

    f.render_widget(list, layout[2]);
}

fn render_process_tree(f: &mut Frame, stats: &SharedStats, state: &mut TuiState) {
    let stats = stats.lock().unwrap();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    //header
    let header = Paragraph::new("Process Tree | 'q' back | ↑↓ scroll")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, layout[0]);
    let mut lines = vec![
        Line::from(Span::styled(
            "Process Relationships:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];
    //get root procs
    let mut procs: Vec<_> = stats
        .timeline
        .process_tree
        .iter()
        .filter(|(_, node)| node.parent_tgid.is_none())
        .collect();
    procs.sort_by_key(|(_, node)| std::cmp::Reverse(node.slow_events));

    for (_tgid, node) in procs.iter().take(20) {
        render_process_node(&mut lines, &stats, node, 0);
    }
    if lines.len() == 2 {
        lines.push(Line::from(Span::styled(
            "No process relationships detected yet",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let paragraph = Paragraph::new(lines)
        .block(Block::default().title("Process Tree").borders(Borders::ALL))
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));

    f.render_widget(paragraph, layout[1]);
}

fn render_process_node(lines: &mut Vec<Line>, stats: &Stats, node: &ProcessNode, depth: usize) {
    let indent = "  ".repeat(depth);
    let prefix = if depth > 0 { "└─ " } else { "" };

    let slow_indicator = if node.slow_events > 0 {
        format!(" [{}SLOW]", node.slow_events)
    } else {
        String::new()
    };

    lines.push(Line::from(format!(
        "{}{}{} (PID {}){}",
        indent, prefix, node.comm, node.tgid, slow_indicator
    )));

    for child_tgid in &node.children {
        if let Some(child_node) = stats.timeline.process_tree.get(child_tgid) {
            render_process_node(lines, stats, child_node, depth + 1);
        }
    }
}
