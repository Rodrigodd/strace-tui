use super::app::{App, split_arguments};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub fn draw(f: &mut Frame, app: &mut App) {
    if app.show_help {
        draw_help(f);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header line
            Constraint::Length(1), // Divider
            Constraint::Min(0),    // Main content
            Constraint::Length(1), // Divider
            Constraint::Length(1), // Footer line
        ])
        .split(f.area());

    // Draw header
    draw_header(f, app, chunks[0]);

    // Draw divider
    draw_divider(f, chunks[1]);

    // Draw main list
    draw_list(f, app, chunks[2]);

    // Draw divider
    draw_divider(f, chunks[3]);

    // Draw footer
    draw_footer(f, chunks[4]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let file_name = app
        .file_path
        .as_ref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("strace");

    let header_text = format!(
        "strace-tui: {} | Syscalls: {} | Failed: {} | PIDs: {} | Signals: {}",
        file_name,
        app.summary.total_syscalls,
        app.summary.failed_syscalls,
        app.summary.unique_pids.len(),
        app.summary.signals,
    );

    let header = Paragraph::new(header_text).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    f.render_widget(header, area);
}

fn draw_divider(f: &mut Frame, area: Rect) {
    let divider = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(divider, area);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    use super::app::DisplayLine;
    use super::syscall_colors::syscall_category_color;

    // Calculate scroll offset to keep selected item visible
    let visible_height = area.height as usize; // No borders, use full height
    app.update_visible_height(visible_height);

    if app.selected_line >= app.scroll_offset + visible_height {
        app.scroll_offset = app.selected_line.saturating_sub(visible_height - 1);
    } else if app.selected_line < app.scroll_offset {
        app.scroll_offset = app.selected_line;
    }

    let mut items = Vec::new();

    // Only render items in the visible window
    let start = app.scroll_offset;
    let end = (app.scroll_offset + visible_height).min(app.display_lines.len());
    let width = area.width as usize;

    for line_idx in start..end {
        let display_line = &app.display_lines[line_idx];

        let line_content = match display_line {
            DisplayLine::SyscallHeader { entry_idx } => {
                let entry = &app.entries[*entry_idx];
                let is_expanded = app.expanded_items.contains(entry_idx);
                let arrow = if is_expanded { "▼" } else { "▶" };

                // Determine base style for special cases
                let has_error = entry.errno.is_some();
                let is_signal = entry.signal.is_some();
                let is_exit = entry.exit_info.is_some();

                // For signals and exits, keep the old behavior (whole line colored)
                if is_signal || is_exit {
                    let syscall_info = if is_signal {
                        format!("--- {} ---", entry.syscall_name.to_uppercase())
                    } else {
                        format!("+++ {} +++", entry.syscall_name)
                    };

                    // Get graph for this entry
                    let graph_chars = app.process_graph.render_graph_for_entry(*entry_idx, entry);
                    let has_graph = !graph_chars.is_empty();
                    let graph_len = if has_graph { graph_chars.len() + 4 } else { 0 }; // +4 for "  "+"  "

                    let pid_color = app.process_graph.get_color(entry.pid);
                    let left_part = format!("{} {}", arrow, syscall_info);
                    let left_len = left_part.chars().count();

                    let metadata_pid = format!("[{}]", entry.pid);
                    let metadata_time = format!(" {}", entry.timestamp);
                    let metadata_len = metadata_pid.chars().count() + metadata_time.chars().count();

                    let color = if is_signal {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    };

                    if left_len + graph_len + metadata_len <= width {
                        let padding_len = width.saturating_sub(left_len + graph_len + metadata_len);
                        let padding = " ".repeat(padding_len);

                        let mut spans = vec![Span::styled(left_part, Style::default().fg(color))];
                        spans.push(Span::styled(padding, Style::default()));

                        if has_graph {
                            spans.push(Span::raw("  "));
                            for (ch, ch_color) in graph_chars {
                                spans.push(Span::styled(
                                    ch.to_string(),
                                    Style::default().fg(ch_color),
                                ));
                            }
                            spans.push(Span::raw("  "));
                        }

                        spans.push(Span::styled(metadata_pid, Style::default().fg(pid_color)));
                        spans.push(Span::styled(metadata_time, Style::default().fg(color)));

                        Line::from(spans)
                    } else {
                        let available_for_left = width.saturating_sub(graph_len + metadata_len + 1);
                        let truncated_left = truncate_line(&left_part, available_for_left);

                        let mut spans =
                            vec![Span::styled(truncated_left, Style::default().fg(color))];
                        spans.push(Span::raw(" "));

                        if has_graph {
                            spans.push(Span::raw("  "));
                            for (ch, ch_color) in graph_chars {
                                spans.push(Span::styled(
                                    ch.to_string(),
                                    Style::default().fg(ch_color),
                                ));
                            }
                            spans.push(Span::raw("  "));
                        }

                        spans.push(Span::styled(metadata_pid, Style::default().fg(pid_color)));
                        spans.push(Span::styled(metadata_time, Style::default().fg(color)));

                        Line::from(spans)
                    }
                } else {
                    // Normal syscall - color the syscall name, rest is white or red
                    let args_preview = truncate(&entry.arguments, 30);
                    let ret = entry.return_value.as_deref().unwrap_or("?");

                    // Get graph for this entry
                    let graph_chars = app.process_graph.render_graph_for_entry(*entry_idx, entry);
                    let has_graph = !graph_chars.is_empty();
                    let graph_len = if has_graph { graph_chars.len() + 4 } else { 0 }; // +4 for "  "+"  "

                    // Build the parts
                    let arrow_str = format!("{} ", arrow);
                    let syscall_name = &entry.syscall_name;
                    let args_and_ret = format!("({}) = {}", args_preview, ret);
                    let pid_color = app.process_graph.get_color(entry.pid);
                    let metadata_pid = format!("[{}]", entry.pid);
                    let metadata_time = format!(" {}", entry.timestamp);

                    // Calculate lengths
                    let arrow_len = arrow_str.chars().count();
                    let syscall_len = syscall_name.chars().count();
                    let args_ret_len = args_and_ret.chars().count();
                    let metadata_len = metadata_pid.chars().count() + metadata_time.chars().count();
                    let left_total = arrow_len + syscall_len + args_ret_len;

                    // Determine colors
                    let syscall_color = syscall_category_color(syscall_name);
                    let rest_color = if has_error { Color::Red } else { Color::White };

                    if left_total + graph_len + metadata_len <= width {
                        // Enough space - build with padding
                        let padding_len =
                            width.saturating_sub(left_total + graph_len + metadata_len);
                        let padding = " ".repeat(padding_len);

                        let mut spans = vec![
                            Span::styled(arrow_str, Style::default().fg(rest_color)),
                            Span::styled(
                                syscall_name.to_string(),
                                Style::default().fg(syscall_color),
                            ),
                            Span::styled(args_and_ret, Style::default().fg(rest_color)),
                            Span::styled(padding, Style::default()),
                        ];

                        if has_graph {
                            spans.push(Span::raw("  "));
                            for (ch, ch_color) in graph_chars {
                                spans.push(Span::styled(
                                    ch.to_string(),
                                    Style::default().fg(ch_color),
                                ));
                            }
                            spans.push(Span::raw("  "));
                        }

                        spans.push(Span::styled(metadata_pid, Style::default().fg(pid_color)));
                        spans.push(Span::styled(metadata_time, Style::default().fg(rest_color)));

                        Line::from(spans)
                    } else {
                        // Not enough space - need to truncate
                        let available_for_left = width.saturating_sub(graph_len + metadata_len + 1);

                        // Try to show as much as possible
                        if arrow_len + syscall_len + 5 <= available_for_left {
                            // Can show syscall name and some args
                            let available_for_args =
                                available_for_left.saturating_sub(arrow_len + syscall_len);
                            let truncated_args = truncate_line(&args_and_ret, available_for_args);

                            let mut spans = vec![
                                Span::styled(arrow_str, Style::default().fg(rest_color)),
                                Span::styled(
                                    syscall_name.to_string(),
                                    Style::default().fg(syscall_color),
                                ),
                                Span::styled(truncated_args, Style::default().fg(rest_color)),
                                Span::styled(" ", Style::default()),
                            ];

                            if has_graph {
                                spans.push(Span::raw("  "));
                                for (ch, ch_color) in graph_chars {
                                    spans.push(Span::styled(
                                        ch.to_string(),
                                        Style::default().fg(ch_color),
                                    ));
                                }
                                spans.push(Span::raw("  "));
                            }

                            spans.push(Span::styled(metadata_pid, Style::default().fg(pid_color)));
                            spans
                                .push(Span::styled(metadata_time, Style::default().fg(rest_color)));

                            Line::from(spans)
                        } else {
                            // Very limited space - truncate syscall name too
                            let left_part =
                                format!("{}{}{}", arrow_str, syscall_name, args_and_ret);
                            let truncated = truncate_line(&left_part, available_for_left);

                            let mut spans = vec![
                                Span::styled(truncated, Style::default().fg(rest_color)),
                                Span::styled(" ", Style::default()),
                            ];

                            if has_graph {
                                spans.push(Span::raw("  "));
                                for (ch, ch_color) in graph_chars {
                                    spans.push(Span::styled(
                                        ch.to_string(),
                                        Style::default().fg(ch_color),
                                    ));
                                }
                                spans.push(Span::raw("  "));
                            }

                            spans.push(Span::styled(metadata_pid, Style::default().fg(pid_color)));
                            spans
                                .push(Span::styled(metadata_time, Style::default().fg(rest_color)));

                            Line::from(spans)
                        }
                    }
                }
            }

            DisplayLine::ArgumentsHeader {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let args_expanded = app.expanded_arguments.contains(entry_idx);
                let args_arrow = if args_expanded { "▼" } else { "▶" };
                let args = split_arguments(&entry.arguments);
                let prefix_str = App::tree_prefix_to_string_header(tree_prefix);
                let content = format!("{} Arguments ({})", args_arrow, args.len());
                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(Color::Gray)),
                ])
            }

            DisplayLine::ArgumentLine {
                entry_idx,
                arg_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let args = split_arguments(&entry.arguments);
                if let Some(arg) = args.get(*arg_idx) {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let max_len = width.saturating_sub(prefix_str.len() + 1);
                    let content = truncate(arg, max_len);
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::DarkGray)),
                    ])
                } else {
                    continue;
                }
            }

            DisplayLine::ReturnValue {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let prefix_str = App::tree_prefix_to_string(tree_prefix);
                let content = if entry.errno.is_some() {
                    format!(
                        "Return: {} (error)",
                        entry.return_value.as_deref().unwrap_or("?")
                    )
                } else {
                    format!(
                        "Return: {}",
                        entry.return_value.as_deref().unwrap_or("?")
                    )
                };
                let ret_color = if entry.errno.is_some() {
                    Color::Red
                } else {
                    Color::Green
                };
                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(ret_color)),
                ])
            }

            DisplayLine::Error {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref errno) = entry.errno {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let content = format!("Error: {} ({})", errno.code, errno.message);
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::Red)),
                    ])
                } else {
                    continue;
                }
            }

            DisplayLine::Duration {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                if let Some(dur) = entry.duration {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let content = format!("Duration: {:.6}s", dur);
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::Gray)),
                    ])
                } else {
                    continue;
                }
            }

            DisplayLine::Signal {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref signal) = entry.signal {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let max_len = width.saturating_sub(prefix_str.len() + 9); // "Signal: "
                    let content = format!(
                        "Signal: {} - {}",
                        signal.signal_name,
                        truncate(&signal.details, max_len)
                    );
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::Yellow)),
                    ])
                } else {
                    continue;
                }
            }

            DisplayLine::Exit {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                if let Some(ref exit) = entry.exit_info {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let content = if exit.killed {
                        format!("Killed with signal {}", exit.code)
                    } else {
                        format!("Exited with code {}", exit.code)
                    };
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::Cyan)),
                    ])
                } else {
                    continue;
                }
            }

            DisplayLine::BacktraceHeader {
                entry_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let bt_expanded = app.expanded_backtraces.contains(entry_idx);
                let bt_arrow = if bt_expanded { "▼" } else { "▶" };
                let prefix_str = App::tree_prefix_to_string_header(tree_prefix);
                let content = format!(
                    "{} Backtrace ({} frames)",
                    bt_arrow,
                    entry.backtrace.len()
                );
                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(Color::Magenta)),
                ])
            }

            DisplayLine::BacktraceFrame {
                entry_idx,
                frame_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let frame = &entry.backtrace[*frame_idx];
                let prefix_str = App::tree_prefix_to_string(tree_prefix);

                let func = frame.function.as_deref().unwrap_or("");
                let offset = frame.offset.as_deref().unwrap_or("");
                let func_info = if !func.is_empty() && !offset.is_empty() {
                    format!("({}+{})", func, offset)
                } else if !func.is_empty() {
                    format!("({})", func)
                } else {
                    String::new()
                };

                let max_binary_len = width.saturating_sub(prefix_str.len() + 10);
                let content = format!(
                    "{}{} [{}]",
                    truncate(&frame.binary, max_binary_len),
                    func_info,
                    frame.address
                );
                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(Color::DarkGray)),
                ])
            }

            DisplayLine::BacktraceResolved {
                entry_idx,
                frame_idx,
                tree_prefix,
            } => {
                let entry = &app.entries[*entry_idx];
                let frame = &entry.backtrace[*frame_idx];
                if let Some(ref resolved) = frame.resolved {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);

                    let max_file_len = width.saturating_sub(prefix_str.len() + 5);
                    let content = format!(
                        "{}:{}",
                        truncate_path_start(&resolved.file, max_file_len),
                        resolved.line
                    );
                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::Green)),
                    ])
                } else {
                    continue;
                }
            }
        };

        items.push(ListItem::new(line_content));
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    // Calculate which item in the visible list to highlight
    let mut state = ratatui::widgets::ListState::default();
    if app.selected_line >= start && app.selected_line < end {
        state.select(Some(app.selected_line - app.scroll_offset));
    }

    f.render_stateful_widget(list, area, &mut state);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new("↑↓/jk: Navigate | ←→: Collapse/Expand | PgUp/PgDn: Page | Ctrl+U/D: Half | Enter: Toggle | x: Collapse | e/c: All | q: Quit | ?: Help")
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, area);
}

fn draw_help(f: &mut Frame) {
    let help_text = vec![
        Line::from(Span::styled(
            "strace-tui Help",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Navigation:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  ↑/k         Move up one line"),
        Line::from("  ↓/j         Move down one line"),
        Line::from("  PageUp      Scroll up one page"),
        Line::from("  PageDown    Scroll down one page"),
        Line::from("  Ctrl+U      Scroll up half page"),
        Line::from("  Ctrl+D      Scroll down half page"),
        Line::from("  Home/g      Jump to first item"),
        Line::from("  End/G       Jump to last item"),
        Line::from(""),
        Line::from(Span::styled(
            "Actions:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  Enter/Space Toggle expansion"),
        Line::from("  ←           Collapse deepest fold"),
        Line::from("  →           Expand current item"),
        Line::from("  x/Backspace Collapse current item"),
        Line::from("  e           Expand all syscalls"),
        Line::from("  c           Collapse all items"),
        Line::from("  r           Resolve current backtrace"),
        Line::from("  R           Resolve all backtraces (slow!)"),
        Line::from(""),
        Line::from(Span::styled(
            "Other:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  q/Q         Quit"),
        Line::from("  ?/h         Toggle this help"),
        Line::from("  Ctrl+C      Force quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Press ? or Esc to close this help",
            Style::default().fg(Color::Yellow),
        )),
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

fn truncate_path_start(path: &str, max_len: usize) -> String {
    if path.len() <= max_len {
        return path.to_string();
    }

    // Truncate from the start, keeping the end (filename)
    let chars: Vec<char> = path.chars().collect();
    if chars.len() <= max_len {
        return path.to_string();
    }

    let keep_chars = max_len.saturating_sub(3); // Reserve 3 for "..."
    let skip_chars = chars.len() - keep_chars;
    let truncated: String = chars.iter().skip(skip_chars).collect();
    format!("...{}", truncated)
}

fn truncate_line(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    // Count actual character width (not bytes)
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= width {
        s.to_string()
    } else {
        let truncate_at = width.saturating_sub(3);
        let truncated: String = chars.iter().take(truncate_at).collect();
        format!("{}...", truncated)
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
