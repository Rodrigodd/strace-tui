use super::app::{App, SearchState, TreeElement, TreePrefix, split_arguments};
use super::process_graph::ProcessGraph;
use crate::parser::SyscallEntry;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};
use std::collections::{HashMap, HashSet};

/// An execve/execveat attempt made by a process
#[derive(Debug, Clone, PartialEq)]
pub struct ExecInfo {
    pub entry_idx: usize,
    /// argv joined by spaces
    pub argv: String,
    pub ok: bool,
    /// Error code, if the exec failed
    pub errno: Option<String>,
}

/// Per-process information shown in the Processes tab
#[derive(Debug, Clone)]
pub struct ProcessSummary {
    pub pid: u32,
    /// PID/TID that called the fork/clone that created this process
    pub parent_pid: Option<u32>,
    pub is_thread: bool,
    /// Thread group leader, if this is a thread
    pub thread_leader: Option<u32>,
    /// Index of the fork/clone entry that created this process
    pub fork_entry_idx: Option<usize>,
    /// First and last syscalls made by the process itself
    pub first_own_entry_idx: Option<usize>,
    pub last_own_entry_idx: Option<usize>,
    pub execs: Vec<ExecInfo>,
    /// The `+++ exited/killed +++` entry
    pub exit_entry_idx: Option<usize>,
    pub syscall_count: usize,
    pub failed_count: usize,
    pub children: Vec<u32>,
}

impl ProcessSummary {
    /// The first successful exec
    pub fn first_exec(&self) -> Option<&ExecInfo> {
        self.execs.iter().find(|exec| exec.ok)
    }
}

fn is_exec_syscall(name: &str) -> bool {
    matches!(name, "execve" | "execveat")
}

/// Extract the argv of an execve/execveat call from its raw arguments, joined by spaces.
pub fn parse_exec_argv(syscall_name: &str, arguments: &str) -> String {
    let argv_idx = if syscall_name == "execveat" { 2 } else { 1 };
    let args = split_arguments(arguments);
    let Some(argv) = args.get(argv_idx) else {
        return String::new();
    };

    let Some(inner) = argv
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        // Not an array (e.g. a raw pointer), show as is
        return argv.clone();
    };

    split_arguments(inner)
        .iter()
        .map(|item| unquote(item))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Strip the outer quotes of a strace string, keeping escapes and a trailing `...` as is.
fn unquote(item: &str) -> String {
    if let Some(rest) = item.strip_prefix('"')
        && let Some(end) = rest.rfind('"')
    {
        format!("{}{}", &rest[..end], &rest[end + 1..])
    } else {
        item.to_string()
    }
}

/// Build the per-process summaries, sorted by where each process starts in the trace.
pub fn build_process_summaries(
    entries: &[SyscallEntry],
    graph: &ProcessGraph,
) -> Vec<ProcessSummary> {
    let mut infos: Vec<_> = graph.processes.values().collect();
    infos.sort_by_key(|info| info.start_key());
    let mut summaries: Vec<ProcessSummary> = infos
        .into_iter()
        .map(|info| ProcessSummary {
            pid: info.pid,
            parent_pid: info.parent_pid,
            is_thread: info.is_thread,
            thread_leader: None,
            fork_entry_idx: info.fork_entry_idx,
            first_own_entry_idx: None,
            last_own_entry_idx: None,
            execs: Vec::new(),
            exit_entry_idx: None,
            syscall_count: 0,
            failed_count: 0,
            children: Vec::new(),
        })
        .collect();

    let index_by_pid: HashMap<u32, usize> = summaries
        .iter()
        .enumerate()
        .map(|(i, s)| (s.pid, i))
        .collect();

    for (idx, entry) in entries.iter().enumerate() {
        let Some(&i) = index_by_pid.get(&entry.pid) else {
            continue;
        };
        let summary = &mut summaries[i];

        if entry.exit_info.is_some() {
            summary.exit_entry_idx = Some(idx);
            continue;
        }
        if entry.signal.is_some() {
            continue;
        }

        summary.first_own_entry_idx.get_or_insert(idx);
        summary.last_own_entry_idx = Some(idx);

        // A resumed entry is the second half of an unfinished one, already counted
        if entry.is_resumed && entry.unfinished_entry_idx.is_some() {
            continue;
        }

        // For an unfinished entry, the result is in its resumed entry
        let result = entry
            .resumed_entry_idx
            .and_then(|i| entries.get(i))
            .unwrap_or(entry);

        summary.syscall_count += 1;
        if result.errno.is_some() {
            summary.failed_count += 1;
        }

        if is_exec_syscall(&entry.syscall_name) {
            summary.execs.push(ExecInfo {
                entry_idx: idx,
                argv: parse_exec_argv(&entry.syscall_name, &entry.arguments),
                ok: result.return_value.as_deref().map(str::trim) == Some("0"),
                errno: result.errno.as_ref().map(|errno| errno.code.clone()),
            });
        }
    }

    // Children, in order of creation (summaries are already sorted)
    for i in 0..summaries.len() {
        if let Some(parent) = summaries[i].parent_pid
            && let Some(&parent_i) = index_by_pid.get(&parent)
        {
            let pid = summaries[i].pid;
            summaries[parent_i].children.push(pid);
        }
    }

    // Thread group leaders: the first non-thread ancestor
    for i in 0..summaries.len() {
        if !summaries[i].is_thread {
            continue;
        }
        let mut leader = summaries[i].parent_pid;
        let mut steps = 0;
        while let Some(pid) = leader
            && let Some(&j) = index_by_pid.get(&pid)
            && summaries[j].is_thread
            && steps < summaries.len()
        {
            leader = summaries[j].parent_pid;
            steps += 1;
        }
        summaries[i].thread_leader = leader;
    }

    summaries
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLineKind {
    Row,
    Parent,
    StartedBy,
    ExecsHeader,
    Exec(usize),
    FirstSyscall,
    LastSyscall,
    Exit,
    Counts,
    ChildrenHeader,
    Child(usize),
}

#[derive(Debug, Clone)]
pub struct ProcessLine {
    pub pid: u32,
    pub kind: ProcessLineKind,
    pub tree_prefix: TreePrefix,
    pub is_search_match: bool,
}

pub enum ProcessAction {
    None,
    JumpToEntry(usize),
    /// A process was hidden or shown, so the Syscalls tab must be rebuilt
    HiddenChanged,
    OpenFilterModal,
}

pub struct ProcessTabState {
    pub summaries: Vec<ProcessSummary>,
    index_by_pid: HashMap<u32, usize>,
    /// Each process's color in the process graph
    colors: HashMap<u32, Color>,
    pub display_lines: Vec<ProcessLine>,
    pub selected_line: usize,
    pub scroll_offset: usize,
    pub last_visible_height: usize,
    pub expanded: HashSet<u32>,
    /// Processes whose Execs / Children sections are expanded
    pub expanded_execs: HashSet<u32>,
    pub expanded_children: HashSet<u32>,
    pub search_state: SearchState,
    /// Hidden processes, also read by the Syscalls tab
    pub hidden_pids: HashSet<u32>,
    /// Ghost mode: show hidden processes dimmed instead of removing them
    pub show_hidden: bool,
}

const ROOT_PREFIX: TreePrefix = [TreeElement::Null; 4];

impl ProcessTabState {
    pub fn new(entries: &[SyscallEntry], graph: &ProcessGraph) -> Self {
        let summaries = build_process_summaries(entries, graph);
        let index_by_pid = summaries
            .iter()
            .enumerate()
            .map(|(i, s)| (s.pid, i))
            .collect();
        let colors = summaries
            .iter()
            .map(|s| (s.pid, graph.get_color(s.pid)))
            .collect();
        let mut state = Self {
            summaries,
            index_by_pid,
            colors,
            display_lines: Vec::new(),
            selected_line: 0,
            scroll_offset: 0,
            last_visible_height: 20,
            expanded: HashSet::new(),
            expanded_execs: HashSet::new(),
            expanded_children: HashSet::new(),
            search_state: SearchState::new(),
            hidden_pids: HashSet::new(),
            show_hidden: false,
        };
        state.rebuild_display_lines(entries);
        state
    }

    pub fn summary(&self, pid: u32) -> Option<&ProcessSummary> {
        self.index_by_pid.get(&pid).map(|&i| &self.summaries[i])
    }

    pub fn is_hidden(&self, pid: u32) -> bool {
        self.hidden_pids.contains(&pid)
    }

    /// Hide or show a process, keeping the selection valid
    pub fn set_pid_hidden(&mut self, pid: u32, hidden: bool, entries: &[SyscallEntry]) {
        if hidden {
            self.hidden_pids.insert(pid);
        } else {
            self.hidden_pids.remove(&pid);
        }
        self.rebuild_display_lines(entries);
    }

    fn color(&self, pid: u32) -> Color {
        self.colors.get(&pid).copied().unwrap_or(Color::White)
    }

    /// Style for a line referring to another process: its graph color, or dimmed if hidden
    fn reference_style(&self, pid: u32) -> Style {
        if self.is_hidden(pid) {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(self.color(pid))
        }
    }

    /// The command a process runs: its first successful exec, or else the command its parent
    /// was running when it forked it (the last exec before the fork, going up the tree). The flag
    /// is true when the command is inherited.
    pub fn running_command(&self, pid: u32) -> Option<(String, bool)> {
        let summary = self.summary(pid)?;
        if let Some(exec) = summary.first_exec() {
            return Some((exec.argv.clone(), false));
        }

        let mut fork_idx = summary.fork_entry_idx?;
        let mut ancestor = self.summary(summary.parent_pid?)?;
        // Bounded, in case of a cycle in bad data
        for _ in 0..self.summaries.len() {
            if let Some(exec) = ancestor
                .execs
                .iter()
                .rev()
                .find(|exec| exec.ok && exec.entry_idx < fork_idx)
            {
                return Some((exec.argv.clone(), true));
            }
            fork_idx = ancestor.fork_entry_idx?;
            ancestor = self.summary(ancestor.parent_pid?)?;
        }
        None
    }

    /// Text for the collapsed row, and whether it should be dimmed (no exec)
    pub fn command_label(&self, pid: u32) -> (String, bool) {
        let Some(summary) = self.summary(pid) else {
            return (String::new(), true);
        };
        let kind = if summary.is_thread { "thread" } else { "fork" };
        match self.running_command(pid) {
            Some((cmd, false)) => return (cmd, false),
            Some((cmd, true)) => return (format!("{}: {}", kind, cmd), true),
            None => {}
        }
        match summary.parent_pid {
            Some(parent) if summary.is_thread => (format!("thread of {}", parent), true),
            Some(parent) => (format!("fork of {}", parent), true),
            None => ("(no execve)".to_string(), true),
        }
    }

    fn detail_kinds(summary: &ProcessSummary) -> Vec<ProcessLineKind> {
        let mut kinds = Vec::new();
        if summary.parent_pid.is_some() {
            kinds.push(ProcessLineKind::Parent);
        }
        if summary.fork_entry_idx.is_some() {
            kinds.push(ProcessLineKind::StartedBy);
        }
        if !summary.execs.is_empty() {
            kinds.push(ProcessLineKind::ExecsHeader);
        }
        if summary.first_own_entry_idx.is_some() {
            kinds.push(ProcessLineKind::FirstSyscall);
            kinds.push(ProcessLineKind::LastSyscall);
        }
        kinds.push(ProcessLineKind::Exit);
        kinds.push(ProcessLineKind::Counts);
        if !summary.children.is_empty() {
            kinds.push(ProcessLineKind::ChildrenHeader);
        }
        kinds
    }

    pub fn rebuild_display_lines(&mut self, entries: &[SyscallEntry]) {
        let previous = self
            .display_lines
            .get(self.selected_line)
            .map(|line| (line.pid, line.kind));
        let screen_pos = self.selected_line.saturating_sub(self.scroll_offset);

        let mut lines = Vec::new();
        for summary in &self.summaries {
            let pid = summary.pid;
            if !self.show_hidden && self.hidden_pids.contains(&pid) {
                continue;
            }
            lines.push(ProcessLine {
                pid,
                kind: ProcessLineKind::Row,
                tree_prefix: ROOT_PREFIX,
                is_search_match: false,
            });
            if !self.expanded.contains(&pid) {
                continue;
            }

            let kinds = Self::detail_kinds(summary);
            for (i, &kind) in kinds.iter().enumerate() {
                let is_last = i + 1 == kinds.len();
                let prefix = App::build_tree_prefix(&ROOT_PREFIX, is_last);
                lines.push(ProcessLine {
                    pid,
                    kind,
                    tree_prefix: prefix,
                    is_search_match: false,
                });

                let sub_count = match kind {
                    ProcessLineKind::ExecsHeader if self.expanded_execs.contains(&pid) => {
                        summary.execs.len()
                    }
                    ProcessLineKind::ChildrenHeader if self.expanded_children.contains(&pid) => {
                        summary.children.len()
                    }
                    _ => 0,
                };
                let nested = App::build_nested_prefix(&prefix, is_last);
                for j in 0..sub_count {
                    let sub_kind = if kind == ProcessLineKind::ExecsHeader {
                        ProcessLineKind::Exec(j)
                    } else {
                        ProcessLineKind::Child(j)
                    };
                    lines.push(ProcessLine {
                        pid,
                        kind: sub_kind,
                        tree_prefix: App::build_tree_prefix(&nested, j + 1 == sub_count),
                        is_search_match: false,
                    });
                }
            }
        }
        self.display_lines = lines;

        // Keep the selection on the same line, or on the row of the same process
        if let Some((pid, kind)) = previous {
            let pos = self
                .display_lines
                .iter()
                .position(|line| line.pid == pid && line.kind == kind)
                .or_else(|| self.row_line(pid))
                .or_else(|| self.nearest_visible_row(pid));
            if let Some(pos) = pos {
                self.selected_line = pos;
                self.scroll_offset = pos.saturating_sub(screen_pos);
            }
        }
        if self.selected_line >= self.display_lines.len() {
            self.selected_line = self.display_lines.len().saturating_sub(1);
        }

        if !self.search_state.query.is_empty() {
            self.update_search_matches(entries, false);
        }
    }

    fn row_line(&self, pid: u32) -> Option<usize> {
        self.line_of(pid, ProcessLineKind::Row)
    }

    /// Row of the next visible process after `pid` (in list order), or else the previous one
    fn nearest_visible_row(&self, pid: u32) -> Option<usize> {
        let i = *self.index_by_pid.get(&pid)?;
        self.summaries[i + 1..]
            .iter()
            .chain(self.summaries[..i].iter().rev())
            .find_map(|s| self.row_line(s.pid))
    }

    fn line_of(&self, pid: u32, kind: ProcessLineKind) -> Option<usize> {
        self.display_lines
            .iter()
            .position(|line| line.pid == pid && line.kind == kind)
    }

    fn select_row(&mut self, pid: u32) {
        self.select_line(pid, ProcessLineKind::Row);
    }

    fn select_line(&mut self, pid: u32, kind: ProcessLineKind) {
        if let Some(pos) = self.line_of(pid, kind) {
            self.selected_line = pos;
            self.ensure_visible();
        }
    }

    /// For a collapsible section header, whether it is expanded
    pub fn section_expanded(&self, line: &ProcessLine) -> Option<bool> {
        match line.kind {
            ProcessLineKind::ExecsHeader => Some(self.expanded_execs.contains(&line.pid)),
            ProcessLineKind::ChildrenHeader => Some(self.expanded_children.contains(&line.pid)),
            _ => None,
        }
    }

    /// The expanded set of a section header's kind
    fn section_set(&mut self, kind: ProcessLineKind) -> Option<&mut HashSet<u32>> {
        match kind {
            ProcessLineKind::ExecsHeader => Some(&mut self.expanded_execs),
            ProcessLineKind::ChildrenHeader => Some(&mut self.expanded_children),
            _ => None,
        }
    }

    /// Left: collapse the innermost fold around the selected line
    fn collapse_deepest(&mut self, entries: &[SyscallEntry]) {
        let Some(line) = self.selected().cloned() else {
            return;
        };
        let pid = line.pid;
        let header = match line.kind {
            ProcessLineKind::Exec(_) => Some(ProcessLineKind::ExecsHeader),
            ProcessLineKind::Child(_) => Some(ProcessLineKind::ChildrenHeader),
            kind if self.section_expanded(&line) == Some(true) => Some(kind),
            _ => None,
        };

        if let Some(header) = header {
            if let Some(set) = self.section_set(header) {
                set.remove(&pid);
            }
            self.rebuild_display_lines(entries);
            self.select_line(pid, header);
        } else {
            self.expanded.remove(&pid);
            self.expanded_execs.remove(&pid);
            self.expanded_children.remove(&pid);
            self.rebuild_display_lines(entries);
            self.select_row(pid);
        }
    }

    /// Right: expand the selected section header, or the selected process
    fn expand_current(&mut self, entries: &[SyscallEntry]) {
        let Some(line) = self.selected().cloned() else {
            return;
        };
        let changed = match self.section_set(line.kind) {
            Some(set) => set.insert(line.pid),
            None => self.expanded.insert(line.pid),
        };
        if changed {
            self.rebuild_display_lines(entries);
        }
    }

    fn ensure_visible(&mut self) {
        if self.selected_line < self.scroll_offset {
            self.scroll_offset = self.selected_line;
        } else if self.selected_line >= self.scroll_offset + self.last_visible_height {
            self.scroll_offset = self.selected_line.saturating_sub(self.last_visible_height) + 1;
        }
    }

    fn selected(&self) -> Option<&ProcessLine> {
        self.display_lines.get(self.selected_line)
    }

    /// Spans for a detail line (everything except `Row`), without the tree prefix
    pub fn detail_spans(&self, line: &ProcessLine, entries: &[SyscallEntry]) -> Vec<Span<'static>> {
        let Some(summary) = self.summary(line.pid) else {
            return Vec::new();
        };
        let label = Style::default().fg(Color::Gray);
        let value = Style::default().fg(Color::White);
        let dim = Style::default().fg(Color::DarkGray);
        let ts = |idx: usize| {
            entries
                .get(idx)
                .map(|e| e.timestamp.clone())
                .filter(|t| !t.is_empty())
                .map(|t| format!("{} ", t))
                .unwrap_or_default()
        };
        let syscall = |idx: usize| {
            entries
                .get(idx)
                .map(|e| e.syscall_name.clone())
                .unwrap_or_default()
        };

        match line.kind {
            ProcessLineKind::Row => Vec::new(),
            ProcessLineKind::Parent => {
                let Some(parent) = summary.parent_pid else {
                    return Vec::new();
                };
                // Same color as the parent's row, dimmed when it has no exec
                let (cmd, dimmed) = self.command_label(parent);
                let parent_style = self.reference_style(parent);
                let mut spans = vec![
                    Span::styled("Parent: ", label),
                    Span::styled(format!("[{}] ", parent), parent_style),
                    Span::styled(
                        cmd,
                        if dimmed {
                            parent_style.add_modifier(Modifier::DIM)
                        } else {
                            parent_style
                        },
                    ),
                ];
                if let Some(parent_summary) = self.summary(parent)
                    && parent_summary.is_thread
                    && let Some(leader) = parent_summary.thread_leader
                {
                    spans.push(Span::styled(format!(" (thread of {})", leader), dim));
                }
                spans
            }
            ProcessLineKind::StartedBy => {
                let Some(idx) = summary.fork_entry_idx else {
                    return Vec::new();
                };
                vec![
                    Span::styled("Started by: ", label),
                    Span::styled(ts(idx), dim),
                    Span::styled(syscall(idx), value),
                ]
            }
            ProcessLineKind::ExecsHeader => vec![Span::styled(
                format!("Execs ({})", summary.execs.len()),
                label,
            )],
            ProcessLineKind::Exec(i) => {
                let Some(exec) = summary.execs.get(i) else {
                    return Vec::new();
                };
                let mut spans = vec![
                    Span::styled(ts(exec.entry_idx), dim),
                    Span::styled(exec.argv.clone(), if exec.ok { value } else { dim }),
                ];
                if let Some(errno) = &exec.errno {
                    spans.push(Span::styled(
                        format!(" ({})", errno),
                        Style::default().fg(Color::Red),
                    ));
                }
                spans
            }
            ProcessLineKind::FirstSyscall | ProcessLineKind::LastSyscall => {
                let (name, idx) = if line.kind == ProcessLineKind::FirstSyscall {
                    ("First syscall: ", summary.first_own_entry_idx)
                } else {
                    ("Last syscall: ", summary.last_own_entry_idx)
                };
                let Some(idx) = idx else {
                    return Vec::new();
                };
                vec![
                    Span::styled(name, label),
                    Span::styled(ts(idx), dim),
                    Span::styled(syscall(idx), value),
                ]
            }
            ProcessLineKind::Exit => {
                let exit = summary
                    .exit_entry_idx
                    .and_then(|idx| entries.get(idx))
                    .and_then(|e| e.exit_info.as_ref());
                let (text, style) = match exit {
                    Some(exit) if exit.killed => (
                        "killed by signal".to_string(),
                        Style::default().fg(Color::Red),
                    ),
                    Some(exit) => (
                        format!("exited with code {}", exit.code),
                        Style::default().fg(if exit.code == 0 {
                            Color::Green
                        } else {
                            Color::Red
                        }),
                    ),
                    None => ("unknown (no exit seen)".to_string(), dim),
                };
                let mut spans = vec![Span::styled("Exit: ", label)];
                if let Some(idx) = summary.exit_entry_idx {
                    spans.push(Span::styled(ts(idx), dim));
                }
                spans.push(Span::styled(text, style));
                spans
            }
            ProcessLineKind::Counts => vec![
                Span::styled("Syscalls: ", label),
                Span::styled(summary.syscall_count.to_string(), value),
                Span::styled(
                    format!(" ({} failed)", summary.failed_count),
                    if summary.failed_count > 0 {
                        Style::default().fg(Color::Red)
                    } else {
                        dim
                    },
                ),
            ],
            ProcessLineKind::ChildrenHeader => vec![Span::styled(
                format!("Children ({})", summary.children.len()),
                label,
            )],
            ProcessLineKind::Child(i) => {
                let Some(&child) = summary.children.get(i) else {
                    return Vec::new();
                };
                // Same color as the child's row, with an inherited command dimmed
                let child_style = self.reference_style(child);
                let mut spans = vec![Span::styled(format!("[{}] ", child), child_style)];
                if let Some(child_summary) = self.summary(child) {
                    let kind = if child_summary.is_thread {
                        "thread"
                    } else {
                        "fork"
                    };
                    spans.push(Span::styled(kind, dim));
                    if let Some((cmd, inherited)) = self.running_command(child) {
                        spans.push(Span::styled(": ", dim));
                        spans.push(Span::styled(
                            cmd,
                            if inherited {
                                child_style.add_modifier(Modifier::DIM)
                            } else {
                                child_style
                            },
                        ));
                    }
                }
                spans
            }
        }
    }

    fn line_text(&self, line: &ProcessLine, entries: &[SyscallEntry]) -> String {
        if line.kind == ProcessLineKind::Row {
            format!("{} {}", line.pid, self.command_label(line.pid).0)
        } else {
            self.detail_spans(line, entries)
                .iter()
                .map(|span| span.content.as_ref())
                .collect()
        }
    }

    pub fn handle_key(&mut self, event: KeyEvent, entries: &[SyscallEntry]) -> ProcessAction {
        if self.search_state.active {
            self.handle_search_key(event, entries);
            return ProcessAction::None;
        }

        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
        match event.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected_line = self.selected_line.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.selected_line + 1 < self.display_lines.len() {
                    self.selected_line += 1;
                }
            }
            KeyCode::PageUp => self.scroll_page(true, false),
            KeyCode::PageDown => self.scroll_page(false, false),
            KeyCode::Char('u') if ctrl => self.scroll_page(true, true),
            KeyCode::Char('d') if ctrl => self.scroll_page(false, true),
            KeyCode::Home | KeyCode::Char('g') => self.selected_line = 0,
            KeyCode::End | KeyCode::Char('G') => {
                self.selected_line = self.display_lines.len().saturating_sub(1);
            }
            KeyCode::Enter | KeyCode::Char(' ') => return self.activate_current(entries),
            KeyCode::Left => self.collapse_deepest(entries),
            KeyCode::Right => self.expand_current(entries),
            KeyCode::Char('e') => {
                self.expanded = self.summaries.iter().map(|s| s.pid).collect();
                self.rebuild_display_lines(entries);
            }
            KeyCode::Char('c') if !ctrl => {
                let pid = self.selected().map(|line| line.pid);
                self.expanded.clear();
                self.expanded_execs.clear();
                self.expanded_children.clear();
                self.rebuild_display_lines(entries);
                if let Some(pid) = pid {
                    self.select_row(pid);
                }
            }
            KeyCode::Char('h') => {
                if let Some(pid) = self.selected().map(|line| line.pid) {
                    let hidden = !self.is_hidden(pid);
                    self.set_pid_hidden(pid, hidden, entries);
                    return ProcessAction::HiddenChanged;
                }
            }
            KeyCode::Char('.') => {
                self.show_hidden = !self.show_hidden;
                self.rebuild_display_lines(entries);
            }
            KeyCode::Char('H') => return ProcessAction::OpenFilterModal,
            KeyCode::Char('/') => self.start_search(),
            KeyCode::Char('n') if !self.search_state.query.is_empty() => self.search_next(),
            KeyCode::Char('N') if !self.search_state.query.is_empty() => self.search_previous(),
            _ => {}
        }
        ProcessAction::None
    }

    /// Select a process's row, turning on ghost mode if it is hidden
    fn go_to_process(&mut self, pid: u32, entries: &[SyscallEntry]) {
        if self.is_hidden(pid) && !self.show_hidden {
            self.show_hidden = true;
            self.rebuild_display_lines(entries);
        }
        self.select_row(pid);
    }

    /// Enter/Space: toggle a row, or follow a detail line to its target
    fn activate_current(&mut self, entries: &[SyscallEntry]) -> ProcessAction {
        let Some(line) = self.selected().cloned() else {
            return ProcessAction::None;
        };
        let Some(summary) = self.summary(line.pid).cloned() else {
            return ProcessAction::None;
        };

        let entry = match line.kind {
            ProcessLineKind::Row => {
                if self.expanded.remove(&line.pid) {
                    self.expanded_execs.remove(&line.pid);
                    self.expanded_children.remove(&line.pid);
                } else {
                    self.expanded.insert(line.pid);
                }
                self.rebuild_display_lines(entries);
                return ProcessAction::None;
            }
            ProcessLineKind::ExecsHeader | ProcessLineKind::ChildrenHeader => {
                if let Some(set) = self.section_set(line.kind)
                    && !set.remove(&line.pid)
                {
                    set.insert(line.pid);
                }
                self.rebuild_display_lines(entries);
                return ProcessAction::None;
            }
            ProcessLineKind::Parent => {
                if let Some(parent) = summary.parent_pid {
                    self.go_to_process(parent, entries);
                }
                return ProcessAction::None;
            }
            ProcessLineKind::Child(i) => {
                if let Some(&child) = summary.children.get(i) {
                    self.go_to_process(child, entries);
                }
                return ProcessAction::None;
            }
            ProcessLineKind::StartedBy => summary.fork_entry_idx,
            ProcessLineKind::Exec(i) => summary.execs.get(i).map(|exec| exec.entry_idx),
            ProcessLineKind::FirstSyscall => summary.first_own_entry_idx,
            ProcessLineKind::LastSyscall => summary.last_own_entry_idx,
            ProcessLineKind::Exit => summary.exit_entry_idx,
            ProcessLineKind::Counts => None,
        };

        match entry {
            Some(idx) => ProcessAction::JumpToEntry(idx),
            None => ProcessAction::None,
        }
    }

    fn scroll_page(&mut self, up: bool, half: bool) {
        if self.display_lines.is_empty() {
            return;
        }
        let page_size = if half {
            self.last_visible_height / 2
        } else {
            self.last_visible_height
        };

        if up {
            let amount = page_size.min(self.scroll_offset);
            self.scroll_offset -= amount;
            self.selected_line = self.selected_line.saturating_sub(page_size);
        } else {
            let max_scroll = self
                .display_lines
                .len()
                .saturating_sub(self.last_visible_height);
            self.scroll_offset = (self.scroll_offset + page_size).min(max_scroll);
            self.selected_line = (self.selected_line + page_size).min(self.display_lines.len() - 1);
        }
    }

    fn start_search(&mut self) {
        self.search_state.active = true;
        self.search_state.original_position = self.selected_line;
        self.search_state.original_scroll = self.scroll_offset;
        self.search_state.query.clear();
        self.search_state.matches.clear();
        self.search_state.current_match_idx = 0;
    }

    fn handle_search_key(&mut self, event: KeyEvent, entries: &[SyscallEntry]) {
        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
        match event.code {
            KeyCode::Char('n') if ctrl => self.search_next(),
            KeyCode::Char('p') if ctrl => self.search_previous(),
            KeyCode::Char(c) if !ctrl => {
                self.search_state.query.push(c);
                self.update_search_matches(entries, true);
            }
            KeyCode::Backspace => {
                self.search_state.query.pop();
                self.update_search_matches(entries, true);
            }
            KeyCode::Enter => self.search_state.active = false,
            KeyCode::Esc => {
                self.selected_line = self.search_state.original_position;
                self.scroll_offset = self.search_state.original_scroll;
                self.search_state.active = false;
                self.search_state.query.clear();
                self.update_search_matches(entries, false);
            }
            _ => {}
        }
    }

    fn update_search_matches(&mut self, entries: &[SyscallEntry], move_cursor: bool) {
        self.search_state.matches.clear();
        let query = self.search_state.query.to_lowercase();

        let flags: Vec<bool> = self
            .display_lines
            .iter()
            .map(|line| {
                !query.is_empty()
                    && self
                        .line_text(line, entries)
                        .to_lowercase()
                        .contains(&query)
            })
            .collect();
        for (idx, (line, is_match)) in self.display_lines.iter_mut().zip(flags).enumerate() {
            line.is_search_match = is_match;
            if is_match {
                self.search_state.matches.push(idx);
            }
        }

        if self.search_state.matches.is_empty() {
            return;
        }
        let match_idx = self
            .search_state
            .matches
            .iter()
            .position(|&idx| idx >= self.selected_line)
            .unwrap_or(0);
        self.search_state.current_match_idx = match_idx;
        if move_cursor {
            self.selected_line = self.search_state.matches[match_idx];
            self.ensure_visible();
        }
    }

    fn search_next(&mut self) {
        if self.search_state.matches.is_empty() {
            return;
        }
        self.search_state.current_match_idx = self
            .search_state
            .matches
            .iter()
            .position(|&idx| idx > self.selected_line)
            .unwrap_or(0);
        self.selected_line = self.search_state.matches[self.search_state.current_match_idx];
        self.ensure_visible();
    }

    fn search_previous(&mut self) {
        if self.search_state.matches.is_empty() {
            return;
        }
        self.search_state.current_match_idx = self
            .search_state
            .matches
            .iter()
            .rposition(|&idx| idx < self.selected_line)
            .unwrap_or(self.search_state.matches.len() - 1);
        self.selected_line = self.search_state.matches[self.search_state.current_match_idx];
        self.ensure_visible();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::StraceParser;

    fn parse(lines: &[&str], merge_resumed: bool) -> Vec<SyscallEntry> {
        StraceParser::new()
            .parse_lines(lines.iter().map(|l| l.to_string()), merge_resumed)
            .unwrap()
    }

    fn tab(lines: &[&str]) -> (Vec<SyscallEntry>, ProcessTabState) {
        let entries = parse(lines, false);
        let graph = ProcessGraph::build(&entries);
        let tab = ProcessTabState::new(&entries, &graph);
        (entries, tab)
    }

    const TRACE: &[&str] = &[
        r#"100 10:00:00.000001 execve("/usr/bin/sh", ["sh", "-c", "ls | wc"], 0x7ffd /* 30 vars */) = 0"#,
        r#"100 10:00:00.000002 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 101"#,
        r#"101 10:00:00.000003 execve("/usr/local/bin/ls", ["ls"], 0x7ffd /* 30 vars */) = -1 ENOENT (No such file or directory)"#,
        r#"101 10:00:00.000004 execve("/usr/bin/ls", ["ls", "-la"], 0x7ffd /* 30 vars */) = 0"#,
        r#"101 10:00:00.000005 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND, exit_signal=0}, 88) = 102"#,
        r#"102 10:00:00.000006 openat(AT_FDCWD, "/nope", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
        r#"102 10:00:00.000007 +++ exited with 0 +++"#,
        r#"101 10:00:00.000008 +++ exited with 2 +++"#,
        r#"100 10:00:00.000009 --- SIGCHLD {si_signo=SIGCHLD} ---"#,
        r#"100 10:00:00.000010 wait4(-1, NULL, 0, NULL) = 101"#,
        r#"100 10:00:00.000011 +++ killed by SIGKILL +++"#,
    ];

    #[test]
    fn test_parse_exec_argv() {
        assert_eq!(
            parse_exec_argv(
                "execve",
                r#""/bin/echo", ["echo", "a, b", "q\"x"], 0x7ffd /* 3 vars */"#
            ),
            r#"echo a, b q\"x"#
        );
        assert_eq!(
            parse_exec_argv(
                "execveat",
                r#"AT_FDCWD, "/bin/ls", ["ls", "long"...], NULL, 0"#
            ),
            "ls long..."
        );
        assert_eq!(
            parse_exec_argv("execve", r#""/bin/ls", 0x1234, NULL"#),
            "0x1234"
        );
        assert_eq!(parse_exec_argv("execve", ""), "");
    }

    #[test]
    fn test_summaries_order_and_tree() {
        let (_, tab) = tab(TRACE);
        let pids: Vec<u32> = tab.summaries.iter().map(|s| s.pid).collect();
        assert_eq!(pids, vec![100, 101, 102]);

        let root = tab.summary(100).unwrap();
        assert_eq!(root.parent_pid, None);
        assert_eq!(root.fork_entry_idx, None);
        assert_eq!(root.children, vec![101]);

        let child = tab.summary(101).unwrap();
        assert_eq!(child.parent_pid, Some(100));
        assert_eq!(child.fork_entry_idx, Some(1));
        assert!(!child.is_thread);
        assert_eq!(child.children, vec![102]);

        let thread = tab.summary(102).unwrap();
        assert!(thread.is_thread);
        assert_eq!(thread.thread_leader, Some(101));
    }

    #[test]
    fn test_command_labels() {
        let (_, tab) = tab(TRACE);
        assert_eq!(tab.command_label(100), ("sh -c ls | wc".to_string(), false));
        // The failed exec is skipped for the label
        assert_eq!(tab.command_label(101), ("ls -la".to_string(), false));
        // Without an exec, the inherited command is used
        assert_eq!(tab.command_label(102), ("thread: ls -la".to_string(), true));
    }

    #[test]
    fn test_fork_label_without_exec() {
        let (_, tab) = tab(&["200 10:00:00 fork() = 201", "201 10:00:00 getpid() = 201"]);
        assert_eq!(tab.command_label(201), ("fork of 200".to_string(), true));
        assert_eq!(tab.command_label(200), ("(no execve)".to_string(), true));
    }

    #[test]
    fn test_running_command() {
        let (_, t) = tab(TRACE);
        assert_eq!(t.running_command(101), Some(("ls -la".to_string(), false)));
        // A thread runs its creator's command at the time of the clone
        assert_eq!(t.running_command(102), Some(("ls -la".to_string(), true)));
        assert_eq!(
            t.running_command(100),
            Some(("sh -c ls | wc".to_string(), false))
        );

        let (_, t) = tab(&[
            r#"400 10:00:00 execve("/bin/a", ["a"], 0x1 /* 1 var */) = 0"#,
            "400 10:00:00 fork() = 401",
            "401 10:00:00 fork() = 402",
            r#"400 10:00:00 execve("/bin/b", ["b"], 0x1 /* 1 var */) = 0"#,
            "402 10:00:00 getpid() = 402",
        ]);
        // Inherited through a fork that never exec'd; the parent's later exec does not count
        assert_eq!(t.running_command(402), Some(("a".to_string(), true)));

        let (_, t) = tab(&["200 10:00:00 fork() = 201", "201 10:00:00 getpid() = 201"]);
        assert_eq!(t.running_command(201), None);
    }

    #[test]
    fn test_execs_counts_and_exit() {
        let (entries, tab) = tab(TRACE);
        let child = tab.summary(101).unwrap();
        assert_eq!(
            child.execs,
            vec![
                ExecInfo {
                    entry_idx: 2,
                    argv: "ls".to_string(),
                    ok: false,
                    errno: Some("ENOENT".to_string()),
                },
                ExecInfo {
                    entry_idx: 3,
                    argv: "ls -la".to_string(),
                    ok: true,
                    errno: None,
                },
            ]
        );
        assert_eq!(child.syscall_count, 3);
        assert_eq!(child.failed_count, 1);
        assert_eq!(child.first_own_entry_idx, Some(2));
        assert_eq!(child.last_own_entry_idx, Some(4));
        assert_eq!(child.exit_entry_idx, Some(7));

        // Signals and exits are not syscalls
        let root = tab.summary(100).unwrap();
        assert_eq!(root.syscall_count, 3);
        assert_eq!(root.last_own_entry_idx, Some(9));
        let exit = entries[root.exit_entry_idx.unwrap()].exit_info.as_ref();
        assert!(exit.unwrap().killed);
    }

    #[test]
    fn test_unfinished_resumed_exec() {
        for merge in [false, true] {
            let entries = parse(
                &[
                    r#"300 10:00:00 execve("/bin/true", ["true"], 0x7ffd /* 1 var */ <unfinished ...>"#,
                    "301 10:00:00 getpid() = 301",
                    "300 10:00:00 <... execve resumed>) = 0",
                ],
                merge,
            );
            let graph = ProcessGraph::build(&entries);
            let summaries = build_process_summaries(&entries, &graph);
            let summary = summaries.iter().find(|s| s.pid == 300).unwrap();
            assert_eq!(summary.syscall_count, 1, "merge={merge}");
            assert_eq!(summary.execs.len(), 1, "merge={merge}");
            assert!(summary.execs[0].ok, "merge={merge}");
            assert_eq!(summary.execs[0].argv, "true", "merge={merge}");
        }
    }

    #[test]
    fn test_display_lines_expand_and_jump() {
        let (entries, mut tab) = tab(TRACE);
        assert_eq!(tab.display_lines.len(), 3);
        let kinds = |tab: &ProcessTabState| -> Vec<ProcessLineKind> {
            tab.display_lines
                .iter()
                .filter(|l| l.pid == 101)
                .map(|l| l.kind)
                .collect()
        };
        let key = |tab: &mut ProcessTabState, code: KeyCode| {
            tab.handle_key(KeyEvent::from(code), &entries)
        };
        let selected = |tab: &ProcessTabState| {
            let line = &tab.display_lines[tab.selected_line];
            (line.pid, line.kind)
        };

        // Expand the child (second row); its sections start collapsed
        tab.selected_line = 1;
        key(&mut tab, KeyCode::Enter);
        assert_eq!(
            kinds(&tab),
            vec![
                ProcessLineKind::Row,
                ProcessLineKind::Parent,
                ProcessLineKind::StartedBy,
                ProcessLineKind::ExecsHeader,
                ProcessLineKind::FirstSyscall,
                ProcessLineKind::LastSyscall,
                ProcessLineKind::Exit,
                ProcessLineKind::Counts,
                ProcessLineKind::ChildrenHeader,
            ]
        );

        // Enter on the Execs header and Right on the Children header expand them
        tab.selected_line = 1 + 3;
        key(&mut tab, KeyCode::Enter);
        tab.selected_line = 1 + 10;
        assert_eq!(selected(&tab), (101, ProcessLineKind::ChildrenHeader));
        key(&mut tab, KeyCode::Right);
        assert_eq!(
            kinds(&tab),
            vec![
                ProcessLineKind::Row,
                ProcessLineKind::Parent,
                ProcessLineKind::StartedBy,
                ProcessLineKind::ExecsHeader,
                ProcessLineKind::Exec(0),
                ProcessLineKind::Exec(1),
                ProcessLineKind::FirstSyscall,
                ProcessLineKind::LastSyscall,
                ProcessLineKind::Exit,
                ProcessLineKind::Counts,
                ProcessLineKind::ChildrenHeader,
                ProcessLineKind::Child(0),
            ]
        );

        // Enter on an exec line jumps to its syscall
        tab.selected_line = 1 + 5;
        assert!(matches!(
            key(&mut tab, KeyCode::Enter),
            ProcessAction::JumpToEntry(3)
        ));

        // Left on an exec line collapses the section and selects its header
        key(&mut tab, KeyCode::Left);
        assert_eq!(selected(&tab), (101, ProcessLineKind::ExecsHeader));
        assert!(!kinds(&tab).contains(&ProcessLineKind::Exec(0)));

        // Enter on a child line selects the child's row
        tab.select_line(101, ProcessLineKind::Child(0));
        key(&mut tab, KeyCode::Enter);
        assert_eq!(selected(&tab), (102, ProcessLineKind::Row));

        // Enter on the parent line selects the parent's row
        tab.select_line(101, ProcessLineKind::Parent);
        key(&mut tab, KeyCode::Enter);
        assert_eq!(tab.selected_line, 0);

        // Left on a collapsed header collapses the process and resets its sections
        tab.select_line(101, ProcessLineKind::ChildrenHeader);
        key(&mut tab, KeyCode::Left);
        assert_eq!(selected(&tab), (101, ProcessLineKind::ChildrenHeader));
        key(&mut tab, KeyCode::Left);
        assert_eq!(selected(&tab), (101, ProcessLineKind::Row));
        key(&mut tab, KeyCode::Right);
        assert!(!kinds(&tab).contains(&ProcessLineKind::Child(0)));
    }

    #[test]
    fn test_hide_process_and_ghost_mode() {
        let (entries, mut tab) = tab(TRACE);
        let rows = |tab: &ProcessTabState| -> Vec<u32> {
            tab.display_lines
                .iter()
                .filter(|l| l.kind == ProcessLineKind::Row)
                .map(|l| l.pid)
                .collect()
        };

        // `h` hides the selected process and moves to the next visible row
        tab.selected_line = 1;
        assert!(matches!(
            tab.handle_key(KeyEvent::from(KeyCode::Char('h')), &entries),
            ProcessAction::HiddenChanged
        ));
        assert!(tab.is_hidden(101));
        assert_eq!(rows(&tab), vec![100, 102]);
        assert_eq!(tab.display_lines[tab.selected_line].pid, 102);

        // Hiding the last row moves back to the previous one
        tab.handle_key(KeyEvent::from(KeyCode::Char('h')), &entries);
        assert_eq!(rows(&tab), vec![100]);
        assert_eq!(tab.display_lines[tab.selected_line].pid, 100);

        // Ghost mode shows hidden rows again, and `h` there shows the process
        tab.handle_key(KeyEvent::from(KeyCode::Char('.')), &entries);
        assert_eq!(rows(&tab), vec![100, 101, 102]);
        tab.selected_line = 2;
        tab.handle_key(KeyEvent::from(KeyCode::Char('h')), &entries);
        assert!(!tab.is_hidden(102));
        assert_eq!(tab.display_lines[tab.selected_line].pid, 102);
    }

    #[test]
    fn test_enter_on_hidden_child_turns_on_ghost_mode() {
        let (entries, mut tab) = tab(TRACE);
        tab.set_pid_hidden(101, true, &entries);

        // Expand the root and its children
        tab.expanded.insert(100);
        tab.expanded_children.insert(100);
        tab.rebuild_display_lines(&entries);
        tab.select_line(100, ProcessLineKind::Child(0));
        tab.handle_key(KeyEvent::from(KeyCode::Enter), &entries);

        assert!(tab.show_hidden);
        let selected = &tab.display_lines[tab.selected_line];
        assert_eq!((selected.pid, selected.kind), (101, ProcessLineKind::Row));
    }

    #[test]
    fn test_search() {
        let (entries, mut tab) = tab(TRACE);
        tab.handle_key(KeyEvent::from(KeyCode::Char('/')), &entries);
        for c in "thread".chars() {
            tab.handle_key(KeyEvent::from(KeyCode::Char(c)), &entries);
        }
        assert_eq!(tab.search_state.matches, vec![2]);
        assert_eq!(tab.selected_line, 2);

        tab.handle_key(KeyEvent::from(KeyCode::Esc), &entries);
        assert_eq!(tab.selected_line, 0);
        assert!(tab.display_lines.iter().all(|l| !l.is_search_match));
    }
}
