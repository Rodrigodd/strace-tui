use super::app::{App, FilterTab, SearchState, Tab};
use super::file_list::{FileCtx, FileLineKind, resource_style};
use super::process_list::ProcessLineKind;
use super::syscall_colors::syscall_category_color;
use crate::parser::split_arguments;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Flex, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header line
            Constraint::Length(1), // Divider
            Constraint::Min(0),    // Main content
            Constraint::Length(1), // Search bar or divider
            Constraint::Length(1), // Footer line
        ])
        .split(f.area());

    // Draw header
    draw_header(f, app, chunks[0]);

    // Draw tab bar
    draw_tab_bar(f, app, chunks[1]);

    // Draw main list
    let search_state = match app.active_tab {
        Tab::Syscalls => {
            draw_list(f, app, chunks[2]);
            &app.search_state
        }
        Tab::Processes => {
            draw_process_list(f, app, chunks[2]);
            &app.process_tab.search_state
        }
        Tab::Files => {
            draw_file_list(f, app, chunks[2]);
            &app.files_tab.search_state
        }
    };

    if search_state.active {
        // Draw search bar
        draw_search_bar(f, search_state, chunks[3]);
    } else {
        // Draw divider
        draw_divider(f, chunks[3]);
    }

    // Draw footer
    draw_footer(f, app, chunks[4]);

    // Draw help modal on top if active
    if app.show_help {
        draw_help(f);
    }

    // Draw filter modal on top if active
    if app.show_filter_modal {
        draw_filter_modal(f, app);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let file_name = app
        .file_path
        .as_ref()
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("strace");

    let header_text = format!(
        "strace-tui: {} | Syscalls: {} | Failed: {} | Unfinished: {} | PIDs: {} | Signals: {}",
        file_name,
        app.summary.total_syscalls,
        app.summary.failed_syscalls,
        app.summary.unfinished,
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

/// Divider line with the tab titles on it. Records each title's area for mouse clicks.
fn draw_tab_bar(f: &mut Frame, app: &mut App, area: Rect) {
    let tabs = Tab::ALL.map(|tab| (tab, tab.title()));
    let spans = tab_title_spans(&tabs, app.active_tab, area, &mut app.tab_hitboxes);

    let divider = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(Line::from(spans));

    f.render_widget(divider, area);
}

/// Spans for tab titles drawn in a block's title, starting at `title_area`'s top-left corner.
/// Records each title's area in `hitboxes` for mouse clicks.
fn tab_title_spans<T: Copy + PartialEq>(
    tabs: &[(T, &str)],
    active: T,
    title_area: Rect,
    hitboxes: &mut Vec<(Rect, T)>,
) -> Vec<Span<'static>> {
    hitboxes.clear();

    let mut spans = vec![Span::raw("─")];
    let mut x = title_area.x + 1;
    for &(tab, name) in tabs {
        let title = format!(" {} ", name);
        let width = title.chars().count() as u16;
        let style = if tab == active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        hitboxes.push((
            Rect::new(x, title_area.y, width, 1).intersection(title_area),
            tab,
        ));
        spans.push(Span::styled(title, style));
        spans.push(Span::raw("─"));
        x += width + 1;
    }
    spans
}

fn draw_divider(f: &mut Frame, area: Rect) {
    let divider = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(divider, area);
}

/// Split syscall name into spans, coloring "unfinished" and "resumed" keywords
fn format_syscall_name_spans(
    syscall_name: &str,
    is_unfinished: bool,
    is_resumed: bool,
    syscall_color: Color,
) -> Vec<Span<'_>> {
    if is_unfinished {
        // Color "unfinished" in yellow, rest in syscall_color
        vec![
            Span::styled(syscall_name.to_string(), Style::default().fg(syscall_color)),
            Span::styled(" <unfinished>", Style::default().fg(Color::Yellow)),
        ]
    } else if is_resumed {
        // Reconstruct format: <... syscall_name resumed>
        // Color "resumed" in green
        vec![
            Span::styled("<... ", Style::default().fg(Color::DarkGray)),
            Span::styled(syscall_name.to_string(), Style::default().fg(syscall_color)),
            Span::styled(" ", Style::default().fg(Color::DarkGray)),
            Span::styled("resumed", Style::default().fg(Color::Green)),
            Span::styled(">", Style::default().fg(Color::DarkGray)),
        ]
    } else {
        vec![Span::styled(
            syscall_name.to_string(),
            Style::default().fg(syscall_color),
        )]
    }
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    use super::app::DisplayLine;

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

    // Hidden processes collapse their graph column, but only when ghost mode is off: with ghost
    // mode on, hidden entries still render (dimmed), so their lanes must stay drawn.
    let empty_hidden = std::collections::HashSet::new();
    let graph_hidden = if app.process_tab.show_hidden {
        &empty_hidden
    } else {
        &app.process_tab.hidden_pids
    };

    for line_idx in start..end {
        let display_line = &app.display_lines[line_idx];

        let line_content = match display_line {
            DisplayLine::SyscallHeader {
                entry_idx,
                is_hidden,
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let is_expanded = app.expanded_items.contains(entry_idx);
                let arrow = if is_expanded { "▼" } else { "▶" };

                // Determine base style for special cases
                let has_error = entry.errno.is_some();
                let is_signal = entry.signal.is_some();
                let is_exit = entry.exit_info.is_some();

                // Override color if hidden
                let base_color_override = if *is_hidden && app.show_hidden {
                    Some(Color::DarkGray)
                } else {
                    None
                };

                if is_signal || is_exit {
                    let syscall_info = if let Some(signal) = &entry.signal {
                        format!("--- {} ---", signal.signal_name)
                    } else if let Some(exit) = &entry.exit_info {
                        format!("+++ exit {} +++", exit.code)
                    } else {
                        unreachable!()
                    };

                    // Get graph for this entry
                    let graph_chars = app
                        .process_graph
                        .render_graph_for_entry(*entry_idx, &app.entries, graph_hidden);
                    let has_graph = !graph_chars.is_empty();
                    let graph_len = if has_graph { graph_chars.len() + 4 } else { 0 }; // +4 for "  "+"  "

                    let pid_color = app.process_graph.get_color(entry.pid);
                    let left_part = format!("{} {}", arrow, syscall_info);
                    let left_len = left_part.chars().count();

                    let metadata_pid = format!("[{}]", entry.pid);
                    let metadata_time = format!(" {}", entry.timestamp);
                    let metadata_len = metadata_pid.chars().count() + metadata_time.chars().count();

                    let color = base_color_override.unwrap_or({
                        if is_signal {
                            Color::Yellow
                        } else {
                            Color::Cyan
                        }
                    });

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
                    let args_preview = &entry.arguments;
                    let ret = entry.return_value.as_deref().unwrap_or("?");

                    // Get graph for this entry
                    let graph_chars = app
                        .process_graph
                        .render_graph_for_entry(*entry_idx, &app.entries, graph_hidden);
                    let has_graph = !graph_chars.is_empty();
                    let graph_len = if has_graph { graph_chars.len() + 4 } else { 0 }; // +4 for "  "+"  "

                    // Build the parts
                    let arrow_str = format!("{} ", arrow);
                    let syscall_name = &entry.syscall_name;
                    let args_and_ret = format!("({}) = {}", args_preview, ret);
                    let pid_color = app.process_graph.get_color(entry.pid);
                    let metadata_pid = format!("[{}]", entry.pid);
                    let metadata_time = format!(" {}", entry.timestamp);

                    // Determine colors
                    let syscall_color =
                        base_color_override.unwrap_or_else(|| syscall_category_color(syscall_name));
                    let rest_color = base_color_override.unwrap_or(if has_error {
                        Color::Red
                    } else {
                        Color::White
                    });

                    // Get syscall name spans (handles unfinished/resumed coloring)
                    let syscall_spans = format_syscall_name_spans(
                        syscall_name,
                        entry.is_unfinished,
                        entry.is_resumed,
                        syscall_color,
                    );

                    // Calculate lengths (sum up all syscall spans)
                    let arrow_len = arrow_str.chars().count();
                    let syscall_len: usize = syscall_spans
                        .iter()
                        .map(|s| s.content.chars().count())
                        .sum();
                    let args_ret_len = args_and_ret.chars().count();
                    let metadata_len = metadata_pid.chars().count() + metadata_time.chars().count();
                    let left_total = arrow_len + syscall_len + args_ret_len;

                    if left_total + graph_len + metadata_len <= width {
                        // Enough space - build with padding
                        let padding_len =
                            width.saturating_sub(left_total + graph_len + metadata_len);
                        let padding = " ".repeat(padding_len);

                        let mut spans =
                            vec![Span::styled(arrow_str, Style::default().fg(rest_color))];
                        spans.extend(syscall_spans);
                        spans.push(Span::styled(args_and_ret, Style::default().fg(rest_color)));
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

                            let mut spans =
                                vec![Span::styled(arrow_str, Style::default().fg(rest_color))];
                            spans.extend(syscall_spans);
                            spans.push(Span::styled(
                                truncated_args,
                                Style::default().fg(rest_color),
                            ));
                            spans.push(Span::styled(" ", Style::default()));

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
                ..
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
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let args = split_arguments(&entry.arguments);
                if let Some(arg) = args.get(*arg_idx) {
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);
                    let refs = resource_ref_spans(app, *entry_idx, Some(*arg_idx));
                    let refs_len: usize = refs.iter().map(|s| s.content.chars().count()).sum();
                    let max_len = width.saturating_sub(prefix_str.len() + 1);
                    let content = truncate(arg, max_len.saturating_sub(refs_len).max(max_len / 2));
                    let mut spans = vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, Style::default().fg(Color::DarkGray)),
                    ];
                    spans.extend(refs);
                    Line::from(spans)
                } else {
                    continue;
                }
            }

            DisplayLine::ReturnValue {
                entry_idx,
                tree_prefix,
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let prefix_str = App::tree_prefix_to_string(tree_prefix);
                let content = if entry.errno.is_some() {
                    format!(
                        "Return: {} (error)",
                        entry.return_value.as_deref().unwrap_or("?")
                    )
                } else {
                    format!("Return: {}", entry.return_value.as_deref().unwrap_or("?"))
                };
                let ret_color = if entry.errno.is_some() {
                    Color::Red
                } else {
                    Color::Green
                };
                let mut spans = vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(ret_color)),
                ];
                spans.extend(resource_ref_spans(app, *entry_idx, None));
                Line::from(spans)
            }

            DisplayLine::Error {
                entry_idx,
                tree_prefix,
                ..
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
                ..
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
                ..
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
                ..
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

            DisplayLine::EntryReference {
                entry_idx,
                tree_prefix,
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let prefix_str = App::tree_prefix_to_string(tree_prefix);

                let content = if let Some(unfinished_idx) = entry.unfinished_entry_idx {
                    format!("Resumed from entry #{}", unfinished_idx + 1)
                } else if let Some(resumed_idx) = entry.resumed_entry_idx {
                    format!("See resumed in entry #{}", resumed_idx + 1)
                } else {
                    continue;
                };

                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(Color::DarkGray)),
                ])
            }

            DisplayLine::BacktraceHeader {
                entry_idx,
                tree_prefix,
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let bt_expanded = app.expanded_backtraces.contains(entry_idx);
                let bt_arrow = if bt_expanded { "▼" } else { "▶" };
                let prefix_str = App::tree_prefix_to_string_header(tree_prefix);

                // Count total addresses and total frames (may differ due to inlining)
                let total_addresses = entry.backtrace.len();
                let total_frames: usize = entry
                    .backtrace
                    .iter()
                    .map(|f| f.resolved.as_ref().map(|r| r.len()).unwrap_or(1))
                    .sum();

                let content = if total_frames > total_addresses {
                    format!(
                        "{} Backtrace ({} addresses, {} frames)",
                        bt_arrow, total_addresses, total_frames
                    )
                } else {
                    format!("{} Backtrace ({} frames)", bt_arrow, total_frames)
                };

                Line::from(vec![
                    Span::styled(prefix_str, Style::default()),
                    Span::styled(content, Style::default().fg(Color::Magenta)),
                ])
            }

            DisplayLine::BacktraceFrame {
                entry_idx,
                frame_idx,
                tree_prefix,
                ..
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
                resolved_idx,
                tree_prefix,
                ..
            } => {
                let entry = &app.entries[*entry_idx];
                let frame = &entry.backtrace[*frame_idx];

                if let Some(resolved_frames) = &frame.resolved {
                    let resolved = &resolved_frames[*resolved_idx];
                    let prefix_str = App::tree_prefix_to_string(tree_prefix);

                    // Use intelligent truncation
                    let content = format_resolved_frame(resolved, prefix_str.len(), width);

                    let style = if resolved.is_inlined {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::ITALIC)
                    } else {
                        Style::default().fg(Color::Green)
                    };

                    Line::from(vec![
                        Span::styled(prefix_str, Style::default()),
                        Span::styled(content, style),
                    ])
                } else {
                    // Shouldn't happen, but fallback
                    Line::from(Span::styled("  <invalid>", Style::default().fg(Color::Red)))
                }
            }
        };

        // Check if this line is a search match
        let is_search_match = match display_line {
            DisplayLine::SyscallHeader {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::ArgumentsHeader {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::ArgumentLine {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::ReturnValue {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::Error {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::Duration {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::Signal {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::Exit {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::EntryReference {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::BacktraceHeader {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::BacktraceFrame {
                is_search_match, ..
            } => *is_search_match,
            DisplayLine::BacktraceResolved {
                is_search_match, ..
            } => *is_search_match,
        };

        // Apply search highlight style
        let item = if is_search_match {
            // Darker yellow for other matches
            ListItem::new(line_content).style(Style::default().bg(Color::Rgb(60, 60, 0)))
        } else {
            ListItem::new(line_content)
        };

        items.push(item);
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

fn draw_process_list(f: &mut Frame, app: &mut App, area: Rect) {
    let tab = &mut app.process_tab;
    let visible_height = area.height as usize;
    tab.last_visible_height = visible_height;

    if tab.selected_line >= tab.scroll_offset + visible_height {
        tab.scroll_offset = tab.selected_line.saturating_sub(visible_height - 1);
    } else if tab.selected_line < tab.scroll_offset {
        tab.scroll_offset = tab.selected_line;
    }

    let tab = &app.process_tab;
    let start = tab.scroll_offset;
    let end = (tab.scroll_offset + visible_height).min(tab.display_lines.len());
    let width = area.width as usize;

    let mut items = Vec::new();
    for line in &tab.display_lines[start..end] {
        let content = if line.kind == ProcessLineKind::Row {
            let arrow = if tab.expanded.contains(&line.pid) {
                "▼"
            } else {
                "▶"
            };
            let (label, dimmed) = tab.command_label(line.pid);
            // Color the row with the process's graph color, dimmed when it has no exec. Hidden
            // processes (only shown in ghost mode) are gray.
            let pid_color = if tab.is_hidden(line.pid) {
                Color::DarkGray
            } else {
                app.process_graph.get_color(line.pid)
            };
            let row_style = Style::default().fg(pid_color);
            let label_style = if dimmed {
                row_style.add_modifier(Modifier::DIM)
            } else {
                row_style
            };

            let graph_hidden = if tab.show_hidden {
                None
            } else {
                Some(&tab.hidden_pids)
            };
            let empty_hidden = std::collections::HashSet::new();
            let graph_chars = app
                .process_graph
                .render_process_start(line.pid, graph_hidden.unwrap_or(&empty_hidden));
            let graph_len = if graph_chars.is_empty() {
                0
            } else {
                graph_chars.len() + 4 // "  " + graph + "  "
            };

            let timestamp = tab
                .summary(line.pid)
                .and_then(|s| s.first_own_entry_idx)
                .and_then(|idx| app.entries.get(idx))
                .map(|e| e.timestamp.as_str())
                .unwrap_or("");
            let metadata_pid = format!("[{}]", line.pid);
            let metadata_time = format!(" {}", timestamp);
            let metadata_len = metadata_pid.chars().count() + metadata_time.chars().count();

            let left = format!("{} {}", arrow, label);
            let available_for_left = width.saturating_sub(graph_len + metadata_len + 1);
            let left = truncate_line(&left, available_for_left);
            let padding = width.saturating_sub(left.chars().count() + graph_len + metadata_len);

            let mut spans = vec![
                Span::styled(left, label_style),
                Span::raw(" ".repeat(padding)),
            ];
            if !graph_chars.is_empty() {
                spans.push(Span::raw("  "));
                for (ch, color) in graph_chars {
                    spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
                }
                spans.push(Span::raw("  "));
            }
            spans.push(Span::styled(metadata_pid, row_style));
            spans.push(Span::styled(metadata_time, row_style));
            Line::from(spans)
        } else {
            // Collapsible section headers get an arrow in place of the horizontal branch
            let prefix = match tab.section_expanded(line) {
                Some(expanded) => format!(
                    "{}{} ",
                    App::tree_prefix_to_string_header(&line.tree_prefix),
                    if expanded { "▼" } else { "▶" }
                ),
                None => App::tree_prefix_to_string(&line.tree_prefix),
            };
            let mut available = width.saturating_sub(prefix.chars().count());
            let mut spans = vec![Span::raw(prefix)];
            // Truncate the detail spans to the available width
            let is_ghost = tab.is_hidden(line.pid);
            for mut span in tab.detail_spans(line, &app.entries) {
                if is_ghost {
                    span.style = span.style.fg(Color::DarkGray);
                }
                if available == 0 {
                    break;
                }
                let len = span.content.chars().count();
                if len <= available {
                    available -= len;
                    spans.push(span);
                } else {
                    spans.push(Span::styled(
                        truncate_line(&span.content, available),
                        span.style,
                    ));
                    available = 0;
                }
            }
            Line::from(spans)
        };

        let item = if line.is_search_match {
            ListItem::new(content).style(Style::default().bg(Color::Rgb(60, 60, 0)))
        } else {
            ListItem::new(content)
        };
        items.push(item);
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    let mut state = ratatui::widgets::ListState::default();
    if tab.selected_line >= start && tab.selected_line < end {
        state.select(Some(tab.selected_line - start));
    }

    f.render_stateful_widget(list, area, &mut state);
}

/// `  → name` for each resource an argument (or the return value, for `None`) refers to
fn resource_ref_spans(app: &App, entry_idx: usize, arg_idx: Option<usize>) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut seen = Vec::new();
    for r in app.files.refs(entry_idx) {
        if r.arg_idx != arg_idx || seen.contains(&r.resource) {
            continue;
        }
        seen.push(r.resource);
        if let Some(resource) = app.files.resources.get(r.resource) {
            spans.push(Span::styled("  → ", Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(
                resource.name.clone(),
                resource_style(resource),
            ));
        }
    }
    spans
}

/// Truncate spans to fit in `available` characters
fn fit_spans(spans: Vec<Span<'static>>, mut available: usize) -> Vec<Span<'static>> {
    let mut fitted = Vec::new();
    for span in spans {
        if available == 0 {
            break;
        }
        let len = span.content.chars().count();
        if len <= available {
            available -= len;
            fitted.push(span);
        } else {
            fitted.push(Span::styled(
                truncate_line(&span.content, available),
                span.style,
            ));
            available = 0;
        }
    }
    fitted
}

fn draw_file_list(f: &mut Frame, app: &mut App, area: Rect) {
    app.sync_files_tab();
    let tab = &mut app.files_tab;
    let visible_height = area.height as usize;
    tab.last_visible_height = visible_height;

    if tab.selected_line >= tab.scroll_offset + visible_height {
        tab.scroll_offset = tab.selected_line.saturating_sub(visible_height - 1);
    } else if tab.selected_line < tab.scroll_offset {
        tab.scroll_offset = tab.selected_line;
    }

    let tab = &app.files_tab;
    let ctx = FileCtx {
        files: &app.files,
        entries: &app.entries,
        hidden_syscalls: &app.hidden_syscalls,
        hidden_pids: &app.process_tab.hidden_pids,
    };
    let graph = &app.process_graph;
    let pid_color = |pid: u32| graph.get_color(pid);
    let start = tab.scroll_offset;
    let end = (tab.scroll_offset + visible_height).min(tab.display_lines.len());
    let width = area.width as usize;

    let mut items = Vec::new();
    for line in &tab.display_lines[start..end] {
        let arrow = |expanded: bool| if expanded { "▼" } else { "▶" };
        let prefix = match (line.kind, tab.is_expanded(line)) {
            (FileLineKind::Resource, Some(expanded)) => format!("{} ", arrow(expanded)),
            (_, Some(expanded)) => format!(
                "{}{} ",
                App::tree_prefix_to_string_header(&line.tree_prefix),
                arrow(expanded)
            ),
            (_, None) => App::tree_prefix_to_string(&line.tree_prefix),
        };

        let (mut left, mut right) = tab.line_spans(line, &ctx, &pid_color);
        if line.is_ghost {
            for span in left.iter_mut().chain(right.iter_mut()) {
                span.style = Style::default().fg(Color::DarkGray);
            }
        }

        let prefix_len = prefix.chars().count();
        let right_len: usize = right.iter().map(|s| s.content.chars().count()).sum();
        let available = width.saturating_sub(prefix_len);
        // Keep the stats right-aligned, dropping them if the name would get too short
        let (left_available, right) = if !right.is_empty() && available >= right_len + 2 + 20 {
            (available - right_len - 2, right)
        } else {
            (available, Vec::new())
        };
        let left = fit_spans(left, left_available);
        let left_len: usize = left.iter().map(|s| s.content.chars().count()).sum();

        // A resource whose accesses all failed gets a red arrow, like its name
        let prefix_style = match app.files.resources.get(line.resource) {
            Some(resource)
                if line.kind == FileLineKind::Resource
                    && !line.is_ghost
                    && resource.all_failed() =>
            {
                resource_style(resource)
            }
            _ => Style::default(),
        };
        let mut spans = vec![Span::styled(prefix, prefix_style)];
        spans.extend(left);
        if !right.is_empty() {
            let padding = available.saturating_sub(left_len + right_len);
            spans.push(Span::raw(" ".repeat(padding)));
            spans.extend(right);
        }
        let content = Line::from(spans);

        let item = if line.is_search_match {
            ListItem::new(content).style(Style::default().bg(Color::Rgb(60, 60, 0)))
        } else {
            ListItem::new(content)
        };
        items.push(item);
    }

    let list = List::new(items).highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    let mut state = ratatui::widgets::ListState::default();
    if tab.selected_line >= start && tab.selected_line < end {
        state.select(Some(tab.selected_line - start));
    }

    f.render_stateful_widget(list, area, &mut state);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    if app.active_tab == Tab::Files {
        let mut footer_text = String::from(
            "?: Help | q: Quit | 1-3: Tab | ↑↓/jk: Nav | ←→: Fold | Enter: Toggle/Jump | e/c: All | .: Ghost | /: Search",
        );
        footer_text.push_str(&format!(" | Files: {}", app.files.resources.len()));
        if app.files_tab.show_hidden {
            footer_text.push_str(" (hidden shown)");
        }
        let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
        f.render_widget(footer, area);
        return;
    }

    if app.active_tab == Tab::Processes {
        let tab = &app.process_tab;
        let mut footer_text = String::from(
            "?: Help | q: Quit | 1-3: Tab | ↑↓/jk: Nav | ←→: Fold | Enter: Toggle/Jump | e/c: All | h: Hide | H: Filter | .: Ghost",
        );
        if !tab.hidden_pids.is_empty() {
            footer_text.push_str(&format!(" | Hidden: {}", tab.hidden_pids.len()));
            if tab.show_hidden {
                footer_text.push_str(" (shown)");
            }
        }
        let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
        f.render_widget(footer, area);
        return;
    }

    let mut footer_text = String::from(
        "?: Help | q: Quit | 1-3: Tab | [Ctrl+] ↑↓/jk: Nav | ←→: Fold | Enter: Toggle/Jump | e/c: All | h/p: Hide | H: Filter | .: Ghost",
    );

    // Add filter status
    let hidden_count = app.hidden_syscalls.len();
    if hidden_count > 0 {
        footer_text.push_str(&format!(" | Hidden: {}", hidden_count));
        if app.show_hidden {
            footer_text.push_str(" (shown)");
        }
    }

    let footer = Paragraph::new(footer_text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(footer, area);
}

fn draw_search_bar(f: &mut Frame, search_state: &SearchState, area: Rect) {
    let match_info = if search_state.matches.is_empty() {
        if search_state.query.is_empty() {
            String::new()
        } else {
            "No matches".to_string()
        }
    } else {
        format!(
            "Match {}/{}",
            search_state.current_match_idx + 1,
            search_state.matches.len()
        )
    };

    let text = if match_info.is_empty() {
        format!(
            "Search: {}█  Enter:accept | Esc: cancel | Ctrl-n/N: next/prev",
            search_state.query
        )
    } else {
        format!(
            "Search: {}█  [{}]  Enter:accept | Esc: cancel | Ctrl-n/N: next/prev",
            search_state.query, match_info
        )
    };

    let paragraph = Paragraph::new(text).style(Style::default().fg(Color::White));

    f.render_widget(paragraph, area);
}

fn draw_help(f: &mut Frame) {
    let left_help_text = vec![
        Line::from(Span::styled(
            "Navigation:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  ↑/k         Move up one line"),
        Line::from("  ↓/j         Move down one line"),
        Line::from("  Ctrl+↑/k    Previous with same PID"),
        Line::from("  Ctrl+↓/j    Next with same PID"),
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
        Line::from("  Enter       Open backtrace in editor"),
        Line::from("  ←           Collapse item"),
        Line::from("  →           Expand item"),
        Line::from("  e           Expand all syscalls"),
        Line::from("  c           Collapse all items"),
        Line::from(""),
        Line::from(Span::styled(
            "Other:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  q/Q         Quit"),
        Line::from("  ?           Toggle this help"),
        Line::from("  Ctrl+C      Force quit"),
    ];

    let right_help_text = vec![
        Line::from(Span::styled(
            "Filtering:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  h           Hide/show current syscall"),
        Line::from("  p           Hide/show current process"),
        Line::from("  h (Procs)   Hide/show current process"),
        Line::from("  H           Open filter modal"),
        Line::from("  .           Toggle show hidden"),
        Line::from(""),
        Line::from(Span::styled(
            "Filter Modal:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  Space/Enter Toggle checkbox"),
        Line::from("  a           Toggle all"),
        Line::from("  ←→/1/2      Syscalls/Processes list"),
        Line::from("  Esc/H/q     Close modal"),
        Line::from(""),
        Line::from(Span::styled(
            "Search:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  /           Start search"),
        Line::from("  n           Next match"),
        Line::from("  N           Previous match"),
        Line::from("  Enter       Accept search"),
        Line::from("  Esc         Cancel search"),
        Line::from(""),
        Line::from(Span::styled(
            "Tabs:",
            Style::default().add_modifier(Modifier::UNDERLINED),
        )),
        Line::from("  1/2/3       Syscalls/Processes/Files"),
        Line::from("  Click       Switch to clicked tab"),
        Line::from("  Enter       Jump to syscall/process"),
        Line::from("  Enter (arg) Jump to its file"),
        Line::from(""),
        Line::from(Span::styled(
            "Press ? or Esc to close help",
            Style::default().fg(Color::Yellow),
        )),
    ];

    let height = left_help_text.len().max(right_help_text.len()) as u16 + 2;
    let width = 39 * 2 + 2; // 57 chars per column + borders
    let area = centered_rect_absolute(width, height, f.area());
    f.render_widget(ratatui::widgets::Clear, area);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let left_help = Paragraph::new(left_help_text)
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM)
                .title("Help"),
        )
        .wrap(Wrap { trim: true });

    let right_help = Paragraph::new(right_help_text)
        .block(Block::default().borders(Borders::RIGHT | Borders::TOP | Borders::BOTTOM))
        .wrap(Wrap { trim: true });

    f.render_widget(left_help, columns[0]);
    f.render_widget(right_help, columns[1]);
}

fn draw_filter_modal(f: &mut Frame, app: &mut App) {
    let area = centered_rect(70, 70, f.area());

    // Split area if search is active
    let (list_area, search_area) = if app.modal_search_state.active {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),    // List
                Constraint::Length(1), // Search bar
            ])
            .split(area);
        (chunks[0], Some(chunks[1]))
    } else {
        (area, None)
    };

    // Tab titles in the top border, after the corner
    let tabs = FilterTab::ALL.map(|tab| (tab, tab.title()));
    let mut title = tab_title_spans(
        &tabs,
        app.filter_modal_state.active_tab,
        Rect {
            x: list_area.x + 1,
            width: list_area.width.saturating_sub(2),
            ..list_area
        },
        &mut app.modal_tab_hitboxes,
    );
    let hints = if app.modal_search_state.active {
        " Search Mode "
    } else {
        " Space: Toggle | a: Toggle All | ←→: Tab | /: Search | q/Esc: Close "
    };
    title.push(Span::raw(hints));

    let app = &*app;
    let modal_state = &app.filter_modal_state;

    // Calculate visible window (account for borders and search bar)
    let visible_height = list_area.height.saturating_sub(2) as usize; // -2 for borders
    let total_items = match modal_state.active_tab {
        FilterTab::Syscalls => modal_state.syscall_list.len(),
        FilterTab::Processes => app.process_tab.summaries.len(),
    };

    // Only render visible items
    let start = modal_state.scroll_offset;
    let end = (start + visible_height).min(total_items);

    // Build list items with checkboxes for visible range
    let items: Vec<ListItem> = (start..end)
        .map(|idx| {
            // Check if this is a search match
            let is_match = app.modal_search_state.matches.contains(&idx);
            let is_current_match = app.modal_search_state.active
                && !app.modal_search_state.matches.is_empty()
                && idx == app.modal_search_state.matches[app.modal_search_state.current_match_idx];

            let (line, is_hidden) = match modal_state.active_tab {
                FilterTab::Syscalls => {
                    let (name, count) = &modal_state.syscall_list[idx];
                    let is_hidden = app.hidden_syscalls.contains(name);
                    let checkbox = if is_hidden { "[ ]" } else { "[✓]" };
                    // Color by category only for visible, non-highlighted rows
                    let name_style = if is_hidden || is_match || is_current_match {
                        Style::default()
                    } else {
                        Style::default().fg(syscall_category_color(name))
                    };
                    let line = Line::from(vec![
                        Span::raw(format!("{} ", checkbox)),
                        Span::styled(name.clone(), name_style),
                        Span::raw(format!(" ({} calls)", count)),
                    ]);
                    (line, is_hidden)
                }
                FilterTab::Processes => {
                    let summary = &app.process_tab.summaries[idx];
                    let pid = summary.pid;
                    let is_hidden = app.process_tab.is_hidden(pid);
                    let checkbox = if is_hidden { "[ ]" } else { "[✓]" };
                    let (label, dimmed) = app.process_tab.command_label(pid);
                    // Colors only for visible, non-highlighted rows; the item style wins otherwise
                    let (pid_style, label_style) = if is_hidden || is_match || is_current_match {
                        (Style::default(), Style::default())
                    } else {
                        let color = app.process_graph.get_color(pid);
                        let label_style = if dimmed {
                            Style::default().add_modifier(Modifier::DIM)
                        } else {
                            Style::default()
                        };
                        (Style::default().fg(color), label_style)
                    };
                    let line = Line::from(vec![
                        Span::raw(format!("{} ", checkbox)),
                        Span::styled(format!("[{}] ", pid), pid_style),
                        Span::styled(label, label_style),
                        Span::raw(format!(" ({} syscalls)", summary.syscall_count)),
                    ]);
                    (line, is_hidden)
                }
            };

            let style = if is_current_match {
                Style::default().bg(Color::Yellow).fg(Color::Black)
            } else if is_match {
                Style::default().bg(Color::DarkGray).fg(Color::Yellow)
            } else if is_hidden {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(title)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    // Set up state for highlighting
    let mut state = ratatui::widgets::ListState::default();
    if modal_state.selected_index >= start && modal_state.selected_index < end {
        state.select(Some(modal_state.selected_index - modal_state.scroll_offset));
    }

    f.render_widget(ratatui::widgets::Clear, list_area);
    f.render_stateful_widget(list, list_area, &mut state);

    // Draw search bar if active
    if let Some(search_area) = search_area {
        draw_modal_search_bar(f, app, search_area);
    }
}

fn draw_modal_search_bar(f: &mut Frame, app: &App, area: Rect) {
    let query = &app.modal_search_state.query;
    let match_info = if app.modal_search_state.matches.is_empty() {
        if query.is_empty() {
            String::new()
        } else {
            " [No matches]".to_string()
        }
    } else {
        format!(
            " [Match {}/{}]",
            app.modal_search_state.current_match_idx + 1,
            app.modal_search_state.matches.len()
        )
    };

    let search_text = format!(
        "Search: {}█{} Enter:accept Esc:cancel n:next N:prev",
        query, match_info
    );

    let search_bar =
        Paragraph::new(search_text).style(Style::default().bg(Color::DarkGray).fg(Color::White));

    f.render_widget(search_bar, area);
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Truncate a string in the middle, keeping start and end
fn truncate_middle(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }

    let ellipsis = "...";
    if max_len <= ellipsis.len() {
        return ellipsis[..max_len].to_string();
    }

    let available = max_len - ellipsis.len();
    let half = available / 2;
    let end_start = s.len() - (available - half);

    format!("{}{}{}", &s[..half], ellipsis, &s[end_start..])
}

/// Intelligently truncate a file path with line:column, prioritizing filename visibility
fn truncate_path_with_line(path: &str, line: u32, column: Option<u32>, max_len: usize) -> String {
    use std::path::Path;

    // Build line info string
    let line_info = if let Some(col) = column {
        format!(":{}:{}", line, col)
    } else {
        format!(":{}", line)
    };

    // Get just the filename
    let filename = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);

    // Full string we want to display
    let full = format!("{}{}", path, line_info);

    if full.len() <= max_len {
        return full;
    }

    // Minimum: filename + line info
    let min_display = format!("{}{}", filename, line_info);
    let min_len = min_display.len();

    if min_len >= max_len {
        // Not even room for filename + line, truncate filename
        if max_len > line_info.len() + 3 {
            let file_budget = max_len - line_info.len() - 3;
            return format!("{}...{}", &filename[..file_budget], line_info);
        } else {
            return truncate(&min_display, max_len);
        }
    }

    // We have room for path prefix + ".../" + filename + line
    let available_for_prefix = max_len.saturating_sub(min_len + 4); // 4 for ".../

    if available_for_prefix == 0 {
        return format!(".../{}{}", filename, line_info);
    }

    // Show start of path + ... + filename
    format!(
        "{}.../{}{}",
        &path[..available_for_prefix],
        filename,
        line_info
    )
}

/// Format a resolved frame with intelligent truncation
fn format_resolved_frame(
    resolved: &crate::parser::ResolvedFrame,
    prefix_len: usize,
    width: usize,
) -> String {
    let inline_tag = if resolved.is_inlined {
        " (inlined)"
    } else {
        ""
    };

    // Calculate available width after prefix, " at ", and tag
    let overhead = prefix_len + 4 + inline_tag.len(); // prefix_len + " at " + tag
    let available = width.saturating_sub(overhead);

    if available < 18 {
        // Too narrow, just show minimal
        return "<truncated>".to_string();
    }

    // Build full location string
    let location = if let Some(col) = resolved.column {
        format!("{}:{}:{}", resolved.file, resolved.line, col)
    } else {
        format!("{}:{}", resolved.file, resolved.line)
    };

    let function_len = resolved.function.len();
    let location_len = location.len();
    let total_needed = function_len + location_len;

    if total_needed <= available {
        // Fits without truncation
        return format!("{} at {}{}", resolved.function, location, inline_tag);
    }

    // Need to truncate - split available space intelligently
    // Give 60% to function, 40% to location (but ensure both have minimums)
    let min_function = 20;
    let min_location = 15;

    let preferred_function = (available * 60 / 100).max(min_function);
    let preferred_location = (available * 40 / 100).max(min_location);

    let (function_budget, location_budget) = if preferred_function + preferred_location > available
    {
        // Can't fit both preferences, scale down
        let total_pref = preferred_function + preferred_location;
        let scale = available as f64 / total_pref as f64;
        (
            (preferred_function as f64 * scale) as usize,
            (preferred_location as f64 * scale) as usize,
        )
    } else {
        (preferred_function, preferred_location)
    };

    // Truncate function name if needed
    let function_display = if function_len > function_budget {
        truncate_middle(&resolved.function, function_budget)
    } else {
        resolved.function.clone()
    };

    // Truncate location intelligently
    let location_display = if location_len > location_budget {
        truncate_path_with_line(
            &resolved.file,
            resolved.line,
            resolved.column,
            location_budget,
        )
    } else {
        location.clone()
    };

    format!("{} at {}{}", function_display, location_display, inline_tag)
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
    let [popup_layout] = Layout::vertical([Constraint::Percentage(percent_y)])
        .flex(Flex::Center)
        .areas(r);

    Layout::horizontal([Constraint::Percentage(percent_x)])
        .flex(Flex::Center)
        .areas::<1>(popup_layout)[0]
}

fn centered_rect_absolute(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + (r.width.saturating_sub(width)) / 2;
    let y = r.y + (r.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width: width.min(r.width),
        height: height.min(r.height),
    }
}
