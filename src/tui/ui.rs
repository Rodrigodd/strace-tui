use super::app::{App, DisplayLine};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    if app.show_help {
        draw_help(f);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(0),     // Main content
            Constraint::Length(1),  // Footer
        ])
        .split(f.area());

    // Draw header
    draw_header(f, app, chunks[0]);

    // Draw main list
    draw_list(f, app, chunks[1]);

    // Draw footer
    draw_footer(f, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let file_name = app.file_path
        .as_ref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("strace");

    let header_text = format!(
        "File: {} | Syscalls: {} | Failed: {} | PIDs: {} | Signals: {}",
        file_name,
        app.summary.total_syscalls,
        app.summary.failed_syscalls,
        app.summary.unique_pids.len(),
        app.summary.signals,
    );

    let header = Paragraph::new(header_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title("strace-tui"));

    f.render_widget(header, area);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    use super::app::DisplayLine;
    
    // Calculate scroll offset to keep selected item visible
    let visible_height = area.height.saturating_sub(2) as usize; // Subtract borders
    if app.selected_line >= app.scroll_offset + visible_height {
        app.scroll_offset = app.selected_line.saturating_sub(visible_height - 1);
    } else if app.selected_line < app.scroll_offset {
        app.scroll_offset = app.selected_line;
    }
    
    let mut items = Vec::new();

    // Only render items in the visible window
    let start = app.scroll_offset;
    let end = (app.scroll_offset + visible_height).min(app.display_lines.len());
    
    for line_idx in start..end {
        let display_line = &app.display_lines[line_idx];
        
        let (line_text, line_style) = match display_line {
            DisplayLine::SyscallHeader { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                let is_expanded = app.expanded_items.contains(entry_idx);
                let arrow = if is_expanded { "▼" } else { "▶" };
                
                let syscall_info = if entry.signal.is_some() {
                    format!("--- {} ---", entry.syscall_name.to_uppercase())
                } else if entry.exit_info.is_some() {
                    format!("+++ {} +++", entry.syscall_name)
                } else {
                    let args_preview = truncate(&entry.arguments, 40);
                    let ret = entry.return_value.as_deref().unwrap_or("?");
                    format!("{}({}) = {}", entry.syscall_name, args_preview, ret)
                };

                let text = format!(
                    "{} {} [{}] {}",
                    arrow,
                    syscall_info,
                    entry.pid,
                    entry.timestamp
                );
                
                let mut style = Style::default();
                if entry.errno.is_some() {
                    style = style.fg(Color::Red);
                } else if entry.signal.is_some() {
                    style = style.fg(Color::Yellow);
                } else if entry.exit_info.is_some() {
                    style = style.fg(Color::Cyan);
                }
                
                (text, style)
            }
            
            DisplayLine::Arguments { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                let text = format!("  ├─ Arguments: {}", truncate(&entry.arguments, 80));
                (text, Style::default().fg(Color::Gray))
            }
            
            DisplayLine::ReturnValue { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                let ret_text = if entry.errno.is_some() {
                    format!("  ├─ Return: {} (error)", entry.return_value.as_deref().unwrap_or("?"))
                } else {
                    format!("  ├─ Return: {}", entry.return_value.as_deref().unwrap_or("?"))
                };
                let ret_style = if entry.errno.is_some() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                };
                (ret_text, ret_style)
            }
            
            DisplayLine::Error { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref errno) = entry.errno {
                    let text = format!("  ├─ Error: {} ({})", errno.code, errno.message);
                    (text, Style::default().fg(Color::Red))
                } else {
                    continue;
                }
            }
            
            DisplayLine::Duration { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                if let Some(dur) = entry.duration {
                    let text = format!("  ├─ Duration: {:.6}s", dur);
                    (text, Style::default().fg(Color::Gray))
                } else {
                    continue;
                }
            }
            
            DisplayLine::Signal { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref signal) = entry.signal {
                    let text = format!("  ├─ Signal: {} - {}", signal.signal_name, truncate(&signal.details, 60));
                    (text, Style::default().fg(Color::Yellow))
                } else {
                    continue;
                }
            }
            
            DisplayLine::Exit { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref exit) = entry.exit_info {
                    let text = if exit.killed {
                        format!("  └─ Killed with signal {}", exit.code)
                    } else {
                        format!("  └─ Exited with code {}", exit.code)
                    };
                    (text, Style::default().fg(Color::Cyan))
                } else {
                    continue;
                }
            }
            
            DisplayLine::BacktraceHeader { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                let bt_expanded = app.expanded_backtraces.contains(entry_idx);
                let bt_arrow = if bt_expanded { "▼" } else { "▶" };
                let text = format!("  └{} Backtrace ({} frames)", bt_arrow, entry.backtrace.len());
                (text, Style::default().fg(Color::Magenta))
            }
            
            DisplayLine::BacktraceFrame { entry_idx, frame_idx } => {
                let entry = &app.entries[*entry_idx];
                let frame = &entry.backtrace[*frame_idx];
                let is_last = *frame_idx == entry.backtrace.len() - 1;
                let tree_char = if is_last { "└─" } else { "├─" };
                
                let func = frame.function.as_deref().unwrap_or("");
                let offset = frame.offset.as_deref().unwrap_or("");
                let func_info = if !func.is_empty() && !offset.is_empty() {
                    format!("({}+{})", func, offset)
                } else if !func.is_empty() {
                    format!("({})", func)
                } else {
                    String::new()
                };

                let text = format!(
                    "      {} {}{} [{}]",
                    tree_char,
                    truncate(&frame.binary, 50),
                    func_info,
                    frame.address
                );
                (text, Style::default().fg(Color::DarkGray))
            }
            
            DisplayLine::BacktraceResolved { entry_idx, frame_idx } => {
                let entry = &app.entries[*entry_idx];
                let frame = &entry.backtrace[*frame_idx];
                if let Some(ref resolved) = frame.resolved {
                    let text = format!(
                        "          → {}:{}",
                        truncate(&resolved.file, 60),
                        resolved.line
                    );
                    (text, Style::default().fg(Color::Green))
                } else {
                    continue;
                }
            }
        };
        
        // Don't apply highlight here - let ListState handle it
        items.push(ListItem::new(line_text).style(line_style));
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        );

    // Calculate which item in the visible list to highlight
    let mut state = ratatui::widgets::ListState::default();
    if app.selected_line >= start && app.selected_line < end {
        state.select(Some(app.selected_line - app.scroll_offset));
    }

    f.render_stateful_widget(list, area, &mut state);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new("↑↓/jk: Navigate | Enter: Expand/Toggle | x: Collapse | e: Expand All | c: Collapse All | r: Resolve | q: Quit | ?: Help")
        .style(Style::default().fg(Color::Gray));
    f.render_widget(footer, area);
}

fn draw_help(f: &mut Frame) {
    let help_text = vec![
        Line::from(Span::styled("strace-tui Help", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(Span::styled("Navigation:", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from("  ↑/k         Move up"),
        Line::from("  ↓/j         Move down"),
        Line::from("  PageUp      Scroll up one page"),
        Line::from("  PageDown    Scroll down one page"),
        Line::from("  Home/g      Jump to first item"),
        Line::from("  End/G       Jump to last item"),
        Line::from(""),
        Line::from(Span::styled("Actions:", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from("  Enter/Space Expand syscall or toggle backtrace"),
        Line::from("  x/Backspace Collapse current item"),
        Line::from("  e           Expand all syscalls"),
        Line::from("  c           Collapse all items"),
        Line::from("  r           Resolve current backtrace"),
        Line::from("  R           Resolve all backtraces (slow!)"),
        Line::from(""),
        Line::from(Span::styled("Other:", Style::default().add_modifier(Modifier::UNDERLINED))),
        Line::from("  q/Q         Quit"),
        Line::from("  ?/h         Toggle this help"),
        Line::from("  Ctrl+C      Force quit"),
        Line::from(""),
        Line::from(Span::styled("Press ? or Esc to close this help", Style::default().fg(Color::Yellow))),
    ];

    let help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .wrap(Wrap { trim: true });

    let area = centered_rect(60, 80, f.area());
    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(help, area);
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
