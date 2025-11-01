use crate::collector::{SharedStats, Stats};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

use std::io;
use std::time::Duration;

pub fn run_tui(stats: SharedStats) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|f| {
            let stats = stats.lock().unwrap();

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)])
                .split(f.size());

            // Header
            let header = Paragraph::new("PerfLens - eBPF Performance Monitor | Press 'q' to quit")
                .style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(header, chunks[0]);

            // Main content
            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(chunks[1]);

            // Left: Summary
            let summary_text = vec![
                Line::from(vec![
                    Span::raw("Total slow operations: "),
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
                .map(|(op, count)| Line::from(format!("  {}: {}", op, count)))
                .collect();

            let mut all_lines = summary_text;
            all_lines.append(&mut type_lines);

            let summary = Paragraph::new(all_lines)
                .block(Block::default().title("Summary").borders(Borders::ALL));
            f.render_widget(summary, main_chunks[0]);

            // Right: Top slow processes
            let items: Vec<ListItem> = stats
                .top_slow_processes()
                .iter()
                .map(|(name, ms, op, tgid, pid)| {
                    if tgid == pid {
                        ListItem::new(format!(
                            "{} - {:.2}ms ({}),pid: {} running on main thread",
                            name, ms, op, tgid
                        ))
                    } else {
                        ListItem::new(format!(
                            "{} - {:.2}ms ({}),pid: {}, tid:{}",
                            name, ms, op, tgid, pid
                        ))
                    }
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Slowest Processes")
                        .borders(Borders::ALL),
                )
                .style(Style::default().fg(Color::White));
            f.render_widget(list, main_chunks[1]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
