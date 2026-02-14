use super::app::App;
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
    let mut items = Vec::new();
    let mut visual_index = 0;
    let mut selected_visual_index = 0;

    for (idx, entry) in app.entries.iter().enumerate() {
        let is_selected = idx == app.selected_index;
        let is_expanded = app.expanded_items.contains(&idx);

        if is_selected {
            selected_visual_index = visual_index;
        }

        // Main syscall line
        let line = format_syscall_line(entry, is_expanded);
        let style = get_syscall_style(entry, is_selected);
        
        items.push(ListItem::new(line).style(style));
        visual_index += 1;

        // Expanded details
        if is_expanded {
            // Arguments
            if !entry.arguments.is_empty() {
                let args = format!("  ├─ Arguments: {}", truncate(&entry.arguments, 80));
                items.push(ListItem::new(args).style(Style::default().fg(Color::Gray)));
                visual_index += 1;
            }

            // Return value
            if let Some(ref ret) = entry.return_value {
                let ret_text = if entry.errno.is_some() {
                    format!("  ├─ Return: {} (error)", ret)
                } else {
                    format!("  ├─ Return: {}", ret)
                };
                let ret_style = if entry.errno.is_some() {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                };
                items.push(ListItem::new(ret_text).style(ret_style));
                visual_index += 1;
            }

            // Error details
            if let Some(ref errno) = entry.errno {
                let err_text = format!("  ├─ Error: {} ({})", errno.code, errno.message);
                items.push(ListItem::new(err_text).style(Style::default().fg(Color::Red)));
                visual_index += 1;
            }

            // Duration
            if let Some(dur) = entry.duration {
                let dur_text = format!("  ├─ Duration: {:.6}s", dur);
                items.push(ListItem::new(dur_text).style(Style::default().fg(Color::Gray)));
                visual_index += 1;
            }

            // Signal info
            if let Some(ref signal) = entry.signal {
                let sig_text = format!("  ├─ Signal: {} - {}", signal.signal_name, truncate(&signal.details, 60));
                items.push(ListItem::new(sig_text).style(Style::default().fg(Color::Yellow)));
                visual_index += 1;
            }

            // Exit info
            if let Some(ref exit) = entry.exit_info {
                let exit_text = if exit.killed {
                    format!("  └─ Killed with signal {}", exit.code)
                } else {
                    format!("  └─ Exited with code {}", exit.code)
                };
                items.push(ListItem::new(exit_text).style(Style::default().fg(Color::Cyan)));
                visual_index += 1;
            }

            // Backtrace
            if !entry.backtrace.is_empty() {
                let bt_expanded = app.expanded_backtraces.contains(&idx);
                let bt_arrow = if bt_expanded { "▼" } else { "▶" };
                let bt_text = format!("  └{} Backtrace ({} frames)", bt_arrow, entry.backtrace.len());
                items.push(ListItem::new(bt_text).style(Style::default().fg(Color::Magenta)));
                visual_index += 1;

                // Expanded backtrace frames
                if bt_expanded {
                    for (frame_idx, frame) in entry.backtrace.iter().enumerate() {
                        let is_last = frame_idx == entry.backtrace.len() - 1;
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

                        let frame_text = format!(
                            "      {} {}{} [{}]",
                            tree_char,
                            truncate(&frame.binary, 50),
                            func_info,
                            frame.address
                        );
                        items.push(ListItem::new(frame_text).style(Style::default().fg(Color::DarkGray)));
                        visual_index += 1;

                        // Resolved location
                        if let Some(ref resolved) = frame.resolved {
                            let indent = if is_last { "    " } else { "    " };
                            let loc_text = format!(
                                "{}    → {}:{}",
                                indent,
                                truncate(&resolved.file, 60),
                                resolved.line
                            );
                            items.push(ListItem::new(loc_text).style(Style::default().fg(Color::Green)));
                            visual_index += 1;
                        }
                    }
                }
            }
        }
    }

    // Calculate scroll offset to keep selected item visible
    let visible_height = area.height.saturating_sub(2) as usize; // Subtract borders
    if selected_visual_index >= app.scroll_offset + visible_height {
        app.scroll_offset = selected_visual_index.saturating_sub(visible_height - 1);
    } else if selected_visual_index < app.scroll_offset {
        app.scroll_offset = selected_visual_index;
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        );

    // Calculate which item to highlight based on selected_index
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(selected_visual_index));

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
        Line::from("  Enter/Space Expand item / Toggle backtrace"),
        Line::from("  x/Backspace Collapse current item"),
        Line::from("  e           Expand all items"),
        Line::from("  c           Collapse all items"),
        Line::from("  r           Resolve backtrace for current item"),
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

fn format_syscall_line(entry: &crate::parser::SyscallEntry, is_expanded: bool) -> String {
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

    format!(
        "{} {} [{}] {}",
        arrow,
        syscall_info,
        entry.pid,
        entry.timestamp
    )
}

fn get_syscall_style(entry: &crate::parser::SyscallEntry, is_selected: bool) -> Style {
    let mut style = Style::default();
    
    if entry.errno.is_some() {
        style = style.fg(Color::Red);
    } else if entry.signal.is_some() {
        style = style.fg(Color::Yellow);
    } else if entry.exit_info.is_some() {
        style = style.fg(Color::Cyan);
    }

    if is_selected {
        style = style.add_modifier(Modifier::BOLD);
    }

    style
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
