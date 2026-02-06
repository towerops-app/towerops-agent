use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use super::state::AgentState;

pub fn render(f: &mut Frame, state: &AgentState, scroll_offset: usize) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Length(3), // Stats
            Constraint::Length(8), // Devices
            Constraint::Min(0),    // Events log
        ])
        .split(f.area());

    render_header(f, chunks[0], state);
    render_stats(f, chunks[1], state);
    render_devices(f, chunks[2], state);
    render_events(f, chunks[3], state, scroll_offset);
}

fn render_header(f: &mut Frame, area: Rect, state: &AgentState) {
    let status_color = if state.connected {
        Color::Green
    } else {
        Color::Red
    };

    let status_text = if state.connected {
        "Connected"
    } else {
        "Disconnected"
    };

    let version_str = format!(" | v{}", state.version);
    let uptime_str = format!(" | Uptime: {}", state.format_uptime());

    let header_lines = vec![
        Line::from(vec![
            Span::raw("Status: "),
            Span::styled(
                status_text,
                Style::default()
                    .fg(status_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | Agent ID: "),
            Span::styled(&state.agent_id, Style::default().fg(Color::Cyan)),
            Span::raw(version_str),
        ]),
        Line::from(vec![
            Span::raw("Hostname: "),
            Span::styled(&state.hostname, Style::default().fg(Color::Yellow)),
            Span::raw(uptime_str),
        ]),
    ];

    let header = Paragraph::new(header_lines).block(
        Block::default()
            .title("Towerops Agent")
            .borders(Borders::ALL),
    );

    f.render_widget(header, area);
}

fn render_stats(f: &mut Frame, area: Rect, state: &AgentState) {
    let heartbeat_ago = state
        .last_heartbeat_ago()
        .map(|s| format!("{}s ago", s))
        .unwrap_or_else(|| "never".to_string());

    let heartbeat_str = format!(" | Last Heartbeat: {}", heartbeat_ago);

    let stats_lines = vec![
        Line::from(vec![
            Span::raw("Jobs: "),
            Span::styled(
                format!("{}", state.stats.jobs_received),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" | SNMP: "),
            Span::styled(
                format!("{}", state.stats.snmp_results_sent),
                Style::default().fg(Color::Green),
            ),
            Span::raw(" | MikroTik: "),
            Span::styled(
                format!("{}", state.stats.mikrotik_results_sent),
                Style::default().fg(Color::Green),
            ),
            Span::raw(" | Errors: "),
            Span::styled(
                format!("{}", state.stats.errors),
                Style::default().fg(if state.stats.errors > 0 {
                    Color::Red
                } else {
                    Color::White
                }),
            ),
        ]),
        Line::from(vec![
            Span::raw("Active Pollers: "),
            Span::styled(
                format!("{}", state.active_pollers),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(heartbeat_str),
        ]),
    ];

    let stats = Paragraph::new(stats_lines)
        .block(Block::default().title("Statistics").borders(Borders::ALL));

    f.render_widget(stats, area);
}

fn render_devices(f: &mut Frame, area: Rect, state: &AgentState) {
    let device_items: Vec<ListItem> = state
        .active_devices
        .iter()
        .take(10)
        .map(|device| {
            ListItem::new(Line::from(vec![
                Span::raw("• "),
                Span::styled(device, Style::default().fg(Color::Cyan)),
            ]))
        })
        .collect();

    let more_count = state.active_devices.len().saturating_sub(10);
    let title = if more_count > 0 {
        format!("Active Devices ({} more)", more_count)
    } else {
        "Active Devices".to_string()
    };

    let devices =
        List::new(device_items).block(Block::default().title(title).borders(Borders::ALL));

    f.render_widget(devices, area);
}

fn render_events(f: &mut Frame, area: Rect, state: &AgentState, scroll_offset: usize) {
    let event_items: Vec<ListItem> = state
        .recent_events
        .iter()
        .rev()
        .skip(scroll_offset)
        .take(area.height.saturating_sub(2) as usize)
        .map(|(timestamp, message)| {
            let elapsed = timestamp.elapsed().as_secs();
            let time_str = if elapsed < 60 {
                format!("{}s ago", elapsed)
            } else if elapsed < 3600 {
                format!("{}m ago", elapsed / 60)
            } else {
                format!("{}h ago", elapsed / 3600)
            };

            let color = if message.contains("Error") || message.contains("failed") {
                Color::Red
            } else if message.contains("sent") || message.contains("completed") {
                Color::Green
            } else if message.contains("received") {
                Color::Yellow
            } else {
                Color::White
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{}] ", time_str),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(message, Style::default().fg(color)),
            ]))
        })
        .collect();

    let events = List::new(event_items).block(
        Block::default()
            .title("Recent Events (Press 'q' to quit, ↑/↓ to scroll)")
            .borders(Borders::ALL),
    );

    f.render_widget(events, area);
}
