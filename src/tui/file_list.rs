//! Files tab: every file, pipe, socket, ... touched by the trace, with the fd lifetimes that
//! referred to it and the syscalls that used each of them.

use super::app::{App, SearchState, TreeElement, TreePrefix};
use super::syscall_colors::syscall_category_color;
use crate::parser::{
    AccessStats, FdLifetime, FileAccess, FileAnalysis, FileResource, LifetimeEnd, ResourceKind,
    SyscallEntry, merge_arguments,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use std::collections::HashSet;

/// Color of a resource by its kind
pub fn kind_color(kind: ResourceKind) -> Color {
    match kind {
        ResourceKind::File => Color::White,
        ResourceKind::Directory => Color::LightBlue,
        ResourceKind::Device => Color::Yellow,
        ResourceKind::Pipe => Color::Magenta,
        ResourceKind::Socket => Color::Green,
        ResourceKind::MemFd => Color::Cyan,
        ResourceKind::EventFd
        | ResourceKind::Epoll
        | ResourceKind::TimerFd
        | ResourceKind::SignalFd
        | ResourceKind::Inotify
        | ResourceKind::PidFd
        | ResourceKind::Anon => Color::LightMagenta,
        ResourceKind::Unknown => Color::Gray,
    }
}

/// Style of a resource name: its kind color, or red when every access to it failed
pub fn resource_style(resource: &FileResource) -> Style {
    if resource.all_failed() {
        Style::default().fg(Color::Red).add_modifier(Modifier::DIM)
    } else {
        Style::default().fg(kind_color(resource.kind))
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileLineKind {
    Resource,
    /// Info line `idx` of an expanded resource
    ResourceInfo(usize),
    Lifetime(usize),
    /// Info line `idx` of an expanded lifetime
    LifetimeInfo {
        lifetime: usize,
        idx: usize,
    },
    /// Accesses by path that did not go through an fd
    PathAccesses,
    /// Access `idx` of a lifetime, or of the path accesses when `lifetime` is `None`
    Access {
        lifetime: Option<usize>,
        idx: usize,
    },
}

impl FileLineKind {
    /// The group of accesses a line heads or belongs to
    fn group(self) -> Option<Option<usize>> {
        match self {
            FileLineKind::Resource | FileLineKind::ResourceInfo(_) => None,
            FileLineKind::Lifetime(lt) | FileLineKind::LifetimeInfo { lifetime: lt, .. } => {
                Some(Some(lt))
            }
            FileLineKind::PathAccesses => Some(None),
            FileLineKind::Access { lifetime, .. } => Some(lifetime),
        }
    }

    fn group_header(group: Option<usize>) -> FileLineKind {
        match group {
            Some(lt) => FileLineKind::Lifetime(lt),
            None => FileLineKind::PathAccesses,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileLine {
    pub resource: usize,
    pub kind: FileLineKind,
    pub tree_prefix: TreePrefix,
    pub is_search_match: bool,
    /// Only shown because of ghost mode: every access under it is hidden
    pub is_ghost: bool,
}

pub enum FileAction {
    None,
    JumpToEntry(usize),
}

/// What the Files tab needs from the rest of the app
pub struct FileCtx<'a> {
    pub files: &'a FileAnalysis,
    pub entries: &'a [SyscallEntry],
    pub hidden_syscalls: &'a HashSet<String>,
    pub hidden_pids: &'a HashSet<u32>,
}

impl FileCtx<'_> {
    /// Whether an access is hidden in the Syscalls tab
    fn is_hidden(&self, access: &FileAccess) -> bool {
        self.entries.get(access.entry_idx).is_some_and(|entry| {
            self.hidden_syscalls.contains(&entry.syscall_name)
                || self.hidden_pids.contains(&entry.pid)
        })
    }
}

/// Accesses of a lifetime, or the path accesses for `None`
fn group_accesses(resource: &FileResource, group: Option<usize>) -> &[FileAccess] {
    match group {
        Some(lt) => resource.lifetimes.get(lt).map_or(&[], |l| &l.accesses),
        None => &resource.path_accesses,
    }
}

const ROOT_PREFIX: TreePrefix = [TreeElement::Null; 4];

pub struct FileTabState {
    pub display_lines: Vec<FileLine>,
    pub selected_line: usize,
    pub scroll_offset: usize,
    pub last_visible_height: usize,
    /// Expanded resources
    pub expanded: HashSet<usize>,
    /// Expanded lifetimes, and path access groups (`None`), by resource
    pub expanded_groups: HashSet<(usize, Option<usize>)>,
    pub search_state: SearchState,
    /// Ghost mode: show accesses hidden in the Syscalls tab dimmed instead of removing them
    pub show_hidden: bool,
    /// Hidden syscalls or processes changed since the last rebuild
    pub dirty: bool,
}

impl FileTabState {
    pub fn new(ctx: &FileCtx) -> Self {
        let mut state = Self {
            display_lines: Vec::new(),
            selected_line: 0,
            scroll_offset: 0,
            last_visible_height: 20,
            expanded: HashSet::new(),
            expanded_groups: HashSet::new(),
            search_state: SearchState::new(),
            show_hidden: false,
            dirty: false,
        };
        state.rebuild_display_lines(ctx);
        state
    }

    pub fn rebuild_display_lines(&mut self, ctx: &FileCtx) {
        self.dirty = false;
        let previous = self
            .display_lines
            .get(self.selected_line)
            .map(|line| (line.resource, line.kind));
        let screen_pos = self.selected_line.saturating_sub(self.scroll_offset);

        let mut lines = Vec::new();
        for (r, resource) in ctx.files.resources.iter().enumerate() {
            let mut groups: Vec<Option<usize>> = (0..resource.lifetimes.len()).map(Some).collect();
            if !resource.path_accesses.is_empty() {
                groups.push(None);
            }
            let group_visible = |group: Option<usize>| {
                group_accesses(resource, group)
                    .iter()
                    .any(|a| !ctx.is_hidden(a))
            };
            let resource_visible = groups.iter().any(|&g| group_visible(g));
            if !resource_visible && !self.show_hidden {
                continue;
            }
            let groups: Vec<Option<usize>> = groups
                .into_iter()
                .filter(|&g| self.show_hidden || group_visible(g))
                .collect();
            if groups.is_empty() {
                continue;
            }

            lines.push(FileLine {
                resource: r,
                kind: FileLineKind::Resource,
                tree_prefix: ROOT_PREFIX,
                is_search_match: false,
                is_ghost: !resource_visible,
            });
            if !self.expanded.contains(&r) {
                continue;
            }

            let info_count = resource_info(resource, ctx.entries).len();
            let children = info_count + groups.len();
            for i in 0..info_count {
                lines.push(FileLine {
                    resource: r,
                    kind: FileLineKind::ResourceInfo(i),
                    tree_prefix: App::build_tree_prefix(&ROOT_PREFIX, i + 1 == children),
                    is_search_match: false,
                    is_ghost: !resource_visible,
                });
            }

            for (i, &group) in groups.iter().enumerate() {
                let is_last = info_count + i + 1 == children;
                let prefix = App::build_tree_prefix(&ROOT_PREFIX, is_last);
                lines.push(FileLine {
                    resource: r,
                    kind: FileLineKind::group_header(group),
                    tree_prefix: prefix,
                    is_search_match: false,
                    is_ghost: !group_visible(group),
                });
                if !self.expanded_groups.contains(&(r, group)) {
                    continue;
                }

                let accesses: Vec<(usize, bool)> = group_accesses(resource, group)
                    .iter()
                    .enumerate()
                    .map(|(idx, a)| (idx, ctx.is_hidden(a)))
                    .filter(|&(_, hidden)| self.show_hidden || !hidden)
                    .collect();
                let nested = App::build_nested_prefix(&prefix, is_last);
                let info_count = group
                    .and_then(|lt| resource.lifetimes.get(lt))
                    .map_or(0, |lifetime| lifetime_info(lifetime, ctx.entries).len());
                let children = info_count + accesses.len();
                for idx in 0..info_count {
                    lines.push(FileLine {
                        resource: r,
                        kind: FileLineKind::LifetimeInfo {
                            lifetime: group.unwrap_or_default(),
                            idx,
                        },
                        tree_prefix: App::build_tree_prefix(&nested, idx + 1 == children),
                        is_search_match: false,
                        is_ghost: !group_visible(group),
                    });
                }
                for (j, &(idx, hidden)) in accesses.iter().enumerate() {
                    lines.push(FileLine {
                        resource: r,
                        kind: FileLineKind::Access {
                            lifetime: group,
                            idx,
                        },
                        tree_prefix: App::build_tree_prefix(
                            &nested,
                            info_count + j + 1 == children,
                        ),
                        is_search_match: false,
                        is_ghost: hidden,
                    });
                }
            }
        }
        self.display_lines = lines;

        // Keep the selection on the same line, or on its group or resource
        if let Some((resource, kind)) = previous {
            let pos = self
                .line_of(resource, kind)
                .or_else(|| {
                    let group = kind.group()?;
                    self.line_of(resource, FileLineKind::group_header(group))
                })
                .or_else(|| self.line_of(resource, FileLineKind::Resource))
                .or_else(|| {
                    // The next visible resource, or else the last one before it
                    let after = self
                        .display_lines
                        .iter()
                        .position(|l| l.resource > resource);
                    after.or_else(|| self.display_lines.len().checked_sub(1))
                });
            if let Some(pos) = pos {
                self.selected_line = pos;
                self.scroll_offset = pos.saturating_sub(screen_pos);
            }
        }
        if self.selected_line >= self.display_lines.len() {
            self.selected_line = self.display_lines.len().saturating_sub(1);
        }

        if !self.search_state.query.is_empty() {
            self.update_search_matches(ctx, false);
        }
    }

    fn line_of(&self, resource: usize, kind: FileLineKind) -> Option<usize> {
        self.display_lines
            .iter()
            .position(|line| line.resource == resource && line.kind == kind)
    }

    fn select_line(&mut self, resource: usize, kind: FileLineKind) {
        if let Some(pos) = self.line_of(resource, kind) {
            self.selected_line = pos;
            self.ensure_visible();
        }
    }

    fn selected(&self) -> Option<&FileLine> {
        self.display_lines.get(self.selected_line)
    }

    /// Whether a line can be expanded, and if it is expanded
    pub fn is_expanded(&self, line: &FileLine) -> Option<bool> {
        match line.kind {
            FileLineKind::Resource => Some(self.expanded.contains(&line.resource)),
            FileLineKind::Lifetime(_) | FileLineKind::PathAccesses => {
                let group = line.kind.group()?;
                Some(self.expanded_groups.contains(&(line.resource, group)))
            }
            FileLineKind::Access { .. }
            | FileLineKind::ResourceInfo(_)
            | FileLineKind::LifetimeInfo { .. } => None,
        }
    }

    /// Select the access of a syscall entry, expanding its resource and group and turning on
    /// ghost mode if the access is hidden
    pub fn go_to_access(
        &mut self,
        ctx: &FileCtx,
        resource: usize,
        lifetime: Option<usize>,
        entry_idx: usize,
    ) {
        let Some(res) = ctx.files.resources.get(resource) else {
            return;
        };
        let accesses = group_accesses(res, lifetime);
        let idx = accesses.iter().position(|a| a.entry_idx == entry_idx);
        if idx.is_some_and(|i| ctx.is_hidden(&accesses[i])) {
            self.show_hidden = true;
        }
        self.expanded.insert(resource);
        self.expanded_groups.insert((resource, lifetime));
        self.rebuild_display_lines(ctx);

        let kind = match idx {
            Some(idx) => FileLineKind::Access { lifetime, idx },
            None => FileLineKind::group_header(lifetime),
        };
        let pos = self
            .line_of(resource, kind)
            .or_else(|| self.line_of(resource, FileLineKind::Resource));
        if let Some(pos) = pos {
            self.selected_line = pos;
            // Center the target on screen
            self.scroll_offset = pos.saturating_sub(self.last_visible_height / 2);
        }
    }

    /// Left: collapse the innermost fold around the selected line
    fn collapse_deepest(&mut self, ctx: &FileCtx) {
        let Some(line) = self.selected().cloned() else {
            return;
        };
        let r = line.resource;
        match line.kind {
            FileLineKind::Access { .. } | FileLineKind::LifetimeInfo { .. } => {
                let lifetime = line.kind.group().flatten();
                self.expanded_groups.remove(&(r, lifetime));
                self.rebuild_display_lines(ctx);
                self.select_line(r, FileLineKind::group_header(lifetime));
            }
            FileLineKind::Lifetime(_) | FileLineKind::PathAccesses
                if self.is_expanded(&line) == Some(true) =>
            {
                if let Some(group) = line.kind.group() {
                    self.expanded_groups.remove(&(r, group));
                }
                self.rebuild_display_lines(ctx);
            }
            _ => {
                self.expanded.remove(&r);
                self.rebuild_display_lines(ctx);
                self.select_line(r, FileLineKind::Resource);
            }
        }
    }

    /// Right: expand the selected resource or group
    fn expand_current(&mut self, ctx: &FileCtx) {
        let Some(line) = self.selected().cloned() else {
            return;
        };
        let changed = match line.kind {
            FileLineKind::Resource => self.expanded.insert(line.resource),
            FileLineKind::Lifetime(_) | FileLineKind::PathAccesses => {
                let group = line.kind.group().flatten();
                self.expanded_groups.insert((line.resource, group))
            }
            FileLineKind::Access { .. }
            | FileLineKind::ResourceInfo(_)
            | FileLineKind::LifetimeInfo { .. } => false,
        };
        if changed {
            self.rebuild_display_lines(ctx);
        }
    }

    /// Enter/Space: toggle a resource or group, or jump to an access's syscall
    fn activate_current(&mut self, ctx: &FileCtx) -> FileAction {
        let Some(line) = self.selected().cloned() else {
            return FileAction::None;
        };
        let r = line.resource;
        match line.kind {
            FileLineKind::Resource => {
                if !self.expanded.remove(&r) {
                    self.expanded.insert(r);
                }
            }
            FileLineKind::Lifetime(_) | FileLineKind::PathAccesses => {
                let key = (r, line.kind.group().flatten());
                if !self.expanded_groups.remove(&key) {
                    self.expanded_groups.insert(key);
                }
            }
            FileLineKind::Access { lifetime, idx } => {
                return ctx
                    .files
                    .resources
                    .get(r)
                    .and_then(|res| group_accesses(res, lifetime).get(idx))
                    .map_or(FileAction::None, |a| FileAction::JumpToEntry(a.entry_idx));
            }
            FileLineKind::ResourceInfo(_) | FileLineKind::LifetimeInfo { .. } => {
                return self
                    .info_line(&line, ctx)
                    .and_then(|info| info.entry_idx)
                    .map_or(FileAction::None, FileAction::JumpToEntry);
            }
        }
        self.rebuild_display_lines(ctx);
        FileAction::None
    }

    pub fn handle_key(&mut self, event: KeyEvent, ctx: &FileCtx) -> FileAction {
        if self.search_state.active {
            self.handle_search_key(event, ctx);
            return FileAction::None;
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
            KeyCode::Enter | KeyCode::Char(' ') => return self.activate_current(ctx),
            KeyCode::Left => self.collapse_deepest(ctx),
            KeyCode::Right => self.expand_current(ctx),
            KeyCode::Char('e') => {
                self.expanded = (0..ctx.files.resources.len()).collect();
                self.rebuild_display_lines(ctx);
            }
            KeyCode::Char('c') if !ctrl => {
                let resource = self.selected().map(|line| line.resource);
                self.expanded.clear();
                self.expanded_groups.clear();
                self.rebuild_display_lines(ctx);
                if let Some(resource) = resource {
                    self.select_line(resource, FileLineKind::Resource);
                }
            }
            KeyCode::Char('.') => {
                self.show_hidden = !self.show_hidden;
                self.rebuild_display_lines(ctx);
            }
            KeyCode::Char('/') => self.start_search(),
            KeyCode::Char('n') if !self.search_state.query.is_empty() => self.search_next(),
            KeyCode::Char('N') if !self.search_state.query.is_empty() => self.search_previous(),
            _ => {}
        }
        FileAction::None
    }

    fn ensure_visible(&mut self) {
        if self.selected_line < self.scroll_offset {
            self.scroll_offset = self.selected_line;
        } else if self.selected_line >= self.scroll_offset + self.last_visible_height {
            self.scroll_offset = self.selected_line.saturating_sub(self.last_visible_height) + 1;
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

    // ----- Line contents -----

    /// Contents of an info line
    fn info_line(&self, line: &FileLine, ctx: &FileCtx) -> Option<InfoLine> {
        let resource = ctx.files.resources.get(line.resource)?;
        match line.kind {
            FileLineKind::ResourceInfo(idx) => {
                resource_info(resource, ctx.entries).into_iter().nth(idx)
            }
            FileLineKind::LifetimeInfo { lifetime, idx } => {
                lifetime_info(resource.lifetimes.get(lifetime)?, ctx.entries)
                    .into_iter()
                    .nth(idx)
            }
            _ => None,
        }
    }

    /// Spans of a line, without the tree prefix. The second list holds the fixed-width
    /// columns, shown right-aligned.
    pub fn line_spans(
        &self,
        line: &FileLine,
        ctx: &FileCtx,
        pid_color: &dyn Fn(u32) -> Color,
    ) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        let Some(resource) = ctx.files.resources.get(line.resource) else {
            return (Vec::new(), Vec::new());
        };

        match line.kind {
            FileLineKind::Resource => {
                let left = vec![
                    Span::styled(
                        format!("{:<7} ", resource.kind.label()),
                        Style::default().fg(kind_color(resource.kind)),
                    ),
                    Span::styled(resource.name.clone(), resource_style(resource)),
                ];
                let columns = column_spans(
                    &resource.stats,
                    resource.lifetimes.len(),
                    &resource.pids,
                    pid_color,
                );
                (left, columns)
            }
            FileLineKind::Lifetime(lt) => {
                let Some(lifetime) = resource.lifetimes.get(lt) else {
                    return (Vec::new(), Vec::new());
                };
                let mut left = Vec::new();
                if let Some(first) = lifetime.aliases.first() {
                    left.push(Span::styled(
                        format!("fd {} ", first.fd),
                        Style::default().fg(Color::White),
                    ));
                    left.push(Span::styled(
                        format!("[{}]", first.pid),
                        Style::default().fg(pid_color(first.pid)),
                    ));
                }
                let pids = access_pids(&lifetime.accesses);
                let columns =
                    column_spans(&lifetime.stats, lifetime.aliases.len(), &pids, pid_color);
                (left, columns)
            }
            FileLineKind::PathAccesses => {
                let stats = AccessStats {
                    calls: resource.path_accesses.len(),
                    errors: resource
                        .path_accesses
                        .iter()
                        .filter(|a| {
                            ctx.entries
                                .get(a.entry_idx)
                                .is_some_and(|e| e.errno.is_some())
                        })
                        .count(),
                    ..AccessStats::default()
                };
                let left = vec![Span::styled("By path", Style::default().fg(Color::Gray))];
                let pids = access_pids(&resource.path_accesses);
                (left, column_spans(&stats, 0, &pids, pid_color))
            }
            FileLineKind::ResourceInfo(_) | FileLineKind::LifetimeInfo { .. } => {
                let spans = self
                    .info_line(line, ctx)
                    .map(|info| info.spans(pid_color))
                    .unwrap_or_default();
                (spans, Vec::new())
            }
            FileLineKind::Access { lifetime, idx } => {
                let Some(access) = group_accesses(resource, lifetime).get(idx) else {
                    return (Vec::new(), Vec::new());
                };
                (access_spans(access, ctx.entries, pid_color), Vec::new())
            }
        }
    }

    /// Text of a line for search (the columns are left out)
    fn line_text(&self, line: &FileLine, ctx: &FileCtx) -> String {
        let (left, _) = self.line_spans(line, ctx, &|_| Color::White);
        left.iter().map(|span| span.content.as_ref()).collect()
    }

    // ----- Search -----

    fn start_search(&mut self) {
        self.search_state.active = true;
        self.search_state.original_position = self.selected_line;
        self.search_state.original_scroll = self.scroll_offset;
        self.search_state.query.clear();
        self.search_state.matches.clear();
        self.search_state.current_match_idx = 0;
    }

    fn handle_search_key(&mut self, event: KeyEvent, ctx: &FileCtx) {
        let ctrl = event.modifiers.contains(KeyModifiers::CONTROL);
        match event.code {
            KeyCode::Char('n') if ctrl => self.search_next(),
            KeyCode::Char('p') if ctrl => self.search_previous(),
            KeyCode::Char(c) if !ctrl => {
                self.search_state.query.push(c);
                self.update_search_matches(ctx, true);
            }
            KeyCode::Backspace => {
                self.search_state.query.pop();
                self.update_search_matches(ctx, true);
            }
            KeyCode::Enter => self.search_state.active = false,
            KeyCode::Esc => {
                self.selected_line = self.search_state.original_position;
                self.scroll_offset = self.search_state.original_scroll;
                self.search_state.active = false;
                self.search_state.query.clear();
                self.update_search_matches(ctx, false);
            }
            _ => {}
        }
    }

    fn update_search_matches(&mut self, ctx: &FileCtx, move_cursor: bool) {
        self.search_state.matches.clear();
        let query = self.search_state.query.to_lowercase();

        let flags: Vec<bool> = self
            .display_lines
            .iter()
            .map(|line| {
                !query.is_empty() && self.line_text(line, ctx).to_lowercase().contains(&query)
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

const PID_WIDTH: usize = 11;

/// Bytes in at most 5 characters: `1023B`, `3.0K`, `512K`, `12M`
pub fn format_bytes_short(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{}B", bytes);
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    const UNITS: [char; 5] = ['K', 'M', 'G', 'T', 'P'];
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value < 10.0 {
        format!("{:.1}{}", value, UNITS[unit])
    } else {
        format!("{:.0}{}", value.floor(), UNITS[unit])
    }
}

/// A count in at most 4 characters: `9999`, `12k`, `1.2M`, `123M`
pub fn format_count_short(n: usize) -> String {
    match n {
        0..=9999 => n.to_string(),
        10_000..=999_999 => format!("{}k", n / 1000),
        1_000_000..=9_999_999 => format!("{:.1}M", n as f64 / 1_000_000.0),
        10_000_000..=999_999_999 => format!("{}M", n / 1_000_000),
        _ => format!("{}G", n / 1_000_000_000),
    }
}

/// The first pid, followed by `,...` if there are others
pub fn format_pids_short(pids: &[u32]) -> String {
    match pids {
        [] => String::new(),
        [pid] => format!("{:>7}    ", pid),
        [pid, ..] => format!("{:>7},...", pid),
    }
}

/// Fixed-width columns `R W fds calls err pid`, with zeros left blank
fn column_spans(
    stats: &AccessStats,
    fds: usize,
    pids: &[u32],
    pid_color: &dyn Fn(u32) -> Color,
) -> Vec<Span<'static>> {
    let column = |value: u64, width: usize, text: String, color: Color| {
        let text = if value == 0 { String::new() } else { text };
        Span::styled(format!("{:>width$} ", text), Style::default().fg(color))
    };
    vec![
        column(
            stats.bytes_read,
            5,
            format_bytes_short(stats.bytes_read),
            Color::Green,
        ),
        column(
            stats.bytes_written,
            5,
            format_bytes_short(stats.bytes_written),
            Color::Yellow,
        ),
        column(fds as u64, 4, format_count_short(fds), Color::Gray),
        column(
            stats.calls as u64,
            4,
            format_count_short(stats.calls),
            Color::White,
        ),
        column(
            stats.errors as u64,
            4,
            format_count_short(stats.errors),
            Color::Red,
        ),
        Span::styled(
            format!("{:<PID_WIDTH$}", format_pids_short(pids)),
            Style::default().fg(pids.first().map_or(Color::Gray, |&pid| pid_color(pid))),
        ),
    ]
}

/// Sorted unique pids of some accesses
fn access_pids(accesses: &[FileAccess]) -> Vec<u32> {
    let mut pids: Vec<u32> = accesses.iter().map(|a| a.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

/// A part of an info line
enum InfoPart {
    Text(String, Style),
    Pid(u32),
}

/// A readable detail line of an expanded resource or lifetime
pub struct InfoLine {
    parts: Vec<InfoPart>,
    /// Syscall the line refers to, to jump to on Enter
    entry_idx: Option<usize>,
}

impl InfoLine {
    fn new(label: &str) -> Self {
        InfoLine {
            parts: vec![InfoPart::Text(
                format!("{}: ", label),
                Style::default().fg(Color::Gray),
            )],
            entry_idx: None,
        }
    }

    fn text(mut self, text: impl Into<String>, color: Color) -> Self {
        self.parts
            .push(InfoPart::Text(text.into(), Style::default().fg(color)));
        self
    }

    fn pids(mut self, pids: &[u32]) -> Self {
        for (i, &pid) in pids.iter().enumerate() {
            if i > 0 {
                self = self.text(", ", Color::DarkGray);
            }
            self.parts.push(InfoPart::Pid(pid));
        }
        self
    }

    /// `12:00:01.123 openat`, jumping to that syscall
    fn syscall(mut self, entries: &[SyscallEntry], idx: usize) -> Self {
        self.entry_idx = Some(idx);
        let Some(entry) = entries.get(idx) else {
            return self;
        };
        if !entry.timestamp.is_empty() {
            self = self.text(format!("{} ", entry.timestamp), Color::DarkGray);
        }
        let name = match &entry.exit_info {
            Some(exit) if exit.killed => "killed".to_string(),
            Some(exit) => format!("exit {}", exit.code),
            None => entry.syscall_name.clone(),
        };
        let color = syscall_category_color(&entry.syscall_name);
        self.text(name, color)
    }

    fn spans(&self, pid_color: &dyn Fn(u32) -> Color) -> Vec<Span<'static>> {
        self.parts
            .iter()
            .map(|part| match part {
                InfoPart::Text(text, style) => Span::styled(text.clone(), *style),
                InfoPart::Pid(pid) => {
                    Span::styled(pid.to_string(), Style::default().fg(pid_color(*pid)))
                }
            })
            .collect()
    }
}

fn plural(n: usize, word: &str) -> String {
    format!("{} {}{}", n, word, if n == 1 { "" } else { "s" })
}

/// Info lines shared by resources and lifetimes: calls, bytes and pids
fn stats_info(stats: &AccessStats, pids: &[u32]) -> Vec<InfoLine> {
    let mut lines = Vec::new();
    let mut calls = InfoLine::new("Calls").text(stats.calls.to_string(), Color::White);
    if stats.errors > 0 {
        calls = calls.text(format!(" ({} failed)", stats.errors), Color::Red);
    }
    lines.push(calls);
    for (label, bytes, color) in [
        ("Read", stats.bytes_read, Color::Green),
        ("Written", stats.bytes_written, Color::Yellow),
    ] {
        if bytes > 0 {
            let mut line = InfoLine::new(label).text(format_bytes(bytes), color);
            if bytes >= 1024 {
                line = line.text(
                    format!(" ({})", plural(bytes as usize, "byte")),
                    Color::DarkGray,
                );
            }
            lines.push(line);
        }
    }
    if !pids.is_empty() {
        lines.push(InfoLine::new(if pids.len() == 1 { "PID" } else { "PIDs" }).pids(pids));
    }
    lines
}

/// Info lines of an expanded resource
fn resource_info(resource: &FileResource, entries: &[SyscallEntry]) -> Vec<InfoLine> {
    let mut kind = InfoLine::new("Kind").text(resource.kind.label(), kind_color(resource.kind));
    if resource.all_failed() {
        kind = kind.text(" (every access failed)", Color::Red);
    }
    let mut lines = vec![kind];
    if !resource.lifetimes.is_empty() {
        let inherited = resource
            .lifetimes
            .iter()
            .filter(|l| l.open_entry_idx.is_none())
            .count();
        let mut fds = InfoLine::new("fds").text(resource.lifetimes.len().to_string(), Color::White);
        if inherited > 0 {
            fds = fds.text(format!(" ({} inherited)", inherited), Color::DarkGray);
        }
        lines.push(fds);
    }
    lines.extend(stats_info(&resource.stats, &resource.pids));
    lines.push(InfoLine::new("First access").syscall(entries, resource.first_entry_idx));
    lines
}

/// Info lines of an expanded lifetime
fn lifetime_info(lifetime: &FdLifetime, entries: &[SyscallEntry]) -> Vec<InfoLine> {
    let mut lines = Vec::new();
    let mut opened = InfoLine::new("Opened");
    match lifetime.open_entry_idx {
        Some(idx) => opened = opened.syscall(entries, idx),
        None => opened = opened.text("before the trace (inherited)", Color::White),
    }
    if let Some(flags) = &lifetime.flags {
        opened = opened.text(format!(" ({})", flags), Color::Gray);
    }
    lines.push(opened);

    if let Some(others) = lifetime.aliases.get(1..).filter(|a| !a.is_empty()) {
        let mut aliases = InfoLine::new("Aliases");
        for (i, alias) in others.iter().enumerate() {
            if i > 0 {
                aliases = aliases.text(", ", Color::DarkGray);
            }
            aliases = aliases.text(format!("fd {} ", alias.fd), Color::White);
            aliases
                .parts
                .push(InfoPart::Text("[".into(), Style::default()));
            aliases.parts.push(InfoPart::Pid(alias.pid));
            aliases
                .parts
                .push(InfoPart::Text("]".into(), Style::default()));
        }
        lines.push(aliases);
    }

    let ended = InfoLine::new("Ended");
    lines.push(match lifetime.end {
        LifetimeEnd::Closed { entry_idx } => ended
            .text("closed at ", Color::White)
            .syscall(entries, entry_idx),
        LifetimeEnd::CloseOnExec { entry_idx } => ended
            .text("closed on exec at ", Color::White)
            .syscall(entries, entry_idx),
        LifetimeEnd::ProcessExit { entry_idx } => ended
            .text("process exited at ", Color::White)
            .syscall(entries, entry_idx),
        LifetimeEnd::StillOpen => ended.text("still open at the end of the trace", Color::White),
    });

    lines.extend(stats_info(
        &lifetime.stats,
        &access_pids(&lifetime.accesses),
    ));
    lines
}

/// `time [pid] name(args) = ret`, combining both halves of split syscalls
fn access_spans(
    access: &FileAccess,
    entries: &[SyscallEntry],
    pid_color: &dyn Fn(u32) -> Color,
) -> Vec<Span<'static>> {
    let Some(entry) = entries.get(access.entry_idx) else {
        return Vec::new();
    };
    let finished = entry
        .resumed_entry_idx
        .filter(|_| entry.is_unfinished)
        .and_then(|idx| entries.get(idx));
    let arguments = match finished {
        Some(resumed) => merge_arguments(&entry.arguments, &resumed.arguments),
        None => entry.arguments.clone(),
    };
    let result = finished.unwrap_or(entry);
    let failed = result.errno.is_some();
    let rest = Style::default().fg(if failed { Color::Red } else { Color::White });

    let mut spans = Vec::new();
    if !entry.timestamp.is_empty() {
        spans.push(Span::styled(
            format!("{} ", entry.timestamp),
            Style::default().fg(Color::DarkGray),
        ));
    }
    spans.push(Span::styled(
        format!("[{}] ", entry.pid),
        Style::default().fg(pid_color(entry.pid)),
    ));
    spans.push(Span::styled(
        entry.syscall_name.clone(),
        Style::default().fg(syscall_category_color(&entry.syscall_name)),
    ));
    let ret = match (&result.return_value, &result.errno) {
        (Some(ret), Some(errno)) => format!(" = {} {}", ret, errno.code),
        (Some(ret), None) => format!(" = {}", ret),
        (None, _) if entry.is_unfinished => " <unfinished ...>".to_string(),
        (None, _) => String::new(),
    };
    spans.push(Span::styled(format!("({}){}", arguments, ret), rest));
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{StraceParser, analyze_files};
    use pretty_assertions::assert_eq;

    fn parse(lines: &[&str]) -> (Vec<SyscallEntry>, FileAnalysis) {
        let entries = StraceParser::new()
            .parse_lines(lines.iter().map(|l| l.to_string()), false)
            .unwrap();
        let files = analyze_files(&entries);
        (entries, files)
    }

    const TRACE: &[&str] = &[
        r#"1 clone3({flags=CLONE_VM|CLONE_FILES|CLONE_THREAD}, 88) = 2"#,
        r#"1 openat(AT_FDCWD, "/a", O_RDONLY) = 3"#,
        r#"1 read(3, "x", 1) = 1"#,
        r#"2 read(3, "x", 1) = 1"#,
        r#"1 close(3) = 0"#,
        r#"1 stat("/b", 0x7fff) = -1 ENOENT (No such file or directory)"#,
    ];

    /// Lines other than info lines
    fn kinds(state: &FileTabState) -> Vec<(usize, FileLineKind, bool)> {
        state
            .display_lines
            .iter()
            .filter(|l| {
                !matches!(
                    l.kind,
                    FileLineKind::ResourceInfo(_) | FileLineKind::LifetimeInfo { .. }
                )
            })
            .map(|l| (l.resource, l.kind, l.is_ghost))
            .collect()
    }

    fn selected_kind(state: &FileTabState) -> FileLineKind {
        state.display_lines[state.selected_line].kind
    }

    #[test]
    fn test_expand_and_hidden() {
        let (entries, files) = parse(TRACE);
        let hidden_syscalls = HashSet::new();
        let mut hidden_pids = HashSet::new();
        let ctx = FileCtx {
            files: &files,
            entries: &entries,
            hidden_syscalls: &hidden_syscalls,
            hidden_pids: &hidden_pids,
        };
        let mut state = FileTabState::new(&ctx);
        assert_eq!(
            kinds(&state),
            vec![
                (0, FileLineKind::Resource, false),
                (1, FileLineKind::Resource, false)
            ]
        );

        state.go_to_access(&ctx, 0, Some(0), 3);
        let access = |idx| FileLineKind::Access {
            lifetime: Some(0),
            idx,
        };
        assert_eq!(
            kinds(&state),
            vec![
                (0, FileLineKind::Resource, false),
                (0, FileLineKind::Lifetime(0), false),
                (0, access(0), false),
                (0, access(1), false),
                (0, access(2), false),
                (0, access(3), false),
                (1, FileLineKind::Resource, false),
            ]
        );
        assert_eq!(selected_kind(&state), access(2));

        // Hiding pid 1 leaves only pid 2's read, and /b disappears
        hidden_pids.insert(1);
        let ctx = FileCtx {
            files: &files,
            entries: &entries,
            hidden_syscalls: &hidden_syscalls,
            hidden_pids: &hidden_pids,
        };
        state.rebuild_display_lines(&ctx);
        assert_eq!(
            kinds(&state),
            vec![
                (0, FileLineKind::Resource, false),
                (0, FileLineKind::Lifetime(0), false),
                (0, access(2), false),
            ]
        );
        assert_eq!(selected_kind(&state), access(2));

        // Ghost mode shows them dimmed
        state.show_hidden = true;
        state.rebuild_display_lines(&ctx);
        assert_eq!(
            kinds(&state),
            vec![
                (0, FileLineKind::Resource, false),
                (0, FileLineKind::Lifetime(0), false),
                (0, access(0), true),
                (0, access(1), true),
                (0, access(2), false),
                (0, access(3), true),
                (1, FileLineKind::Resource, true),
            ]
        );
    }

    #[test]
    fn test_line_text() {
        let (entries, files) = parse(TRACE);
        let empty_syscalls = HashSet::new();
        let empty_pids = HashSet::new();
        let ctx = FileCtx {
            files: &files,
            entries: &entries,
            hidden_syscalls: &empty_syscalls,
            hidden_pids: &empty_pids,
        };
        let mut state = FileTabState::new(&ctx);
        state.expanded.insert(0);
        state.expanded.insert(1);
        state.expanded_groups.insert((0, Some(0)));
        state.rebuild_display_lines(&ctx);
        let texts: Vec<String> = state
            .display_lines
            .iter()
            .map(|l| state.line_text(l, &ctx))
            .collect();
        assert_eq!(
            texts,
            vec![
                "file    /a",
                "Kind: file",
                "fds: 1",
                "Calls: 4",
                "Read: 2 B",
                "PIDs: 1, 2",
                "First access: openat",
                "fd 3 [1]",
                "Opened: openat (O_RDONLY)",
                "Ended: closed at close",
                "Calls: 4",
                "Read: 2 B",
                "PIDs: 1, 2",
                "[1] openat(AT_FDCWD, \"/a\", O_RDONLY) = 3",
                "[1] read(3, \"x\", 1) = 1",
                "[2] read(3, \"x\", 1) = 1",
                "[1] close(3) = 0",
                "file    /b",
                "Kind: file (every access failed)",
                "Calls: 1 (1 failed)",
                "PID: 1",
                "First access: stat",
                "By path",
            ]
        );

        // Enter on "First access" jumps to the openat
        state.selected_line = 6;
        assert!(matches!(
            state.activate_current(&ctx),
            FileAction::JumpToEntry(1)
        ));

        let columns = |line: usize| -> String {
            let (_, columns) =
                state.line_spans(&state.display_lines[line], &ctx, &|_| Color::White);
            columns.iter().map(|s| s.content.as_ref()).collect()
        };
        assert_eq!(columns(0), "   2B          1    4            1,...");
        assert_eq!(columns(17), "                    1    1       1    ");
        assert_eq!(columns(22), columns(17));
    }

    #[test]
    fn test_short_formats() {
        let bytes: Vec<String> = [0, 17, 1023, 1024, 3072, 10 * 1024, 1023 * 1024, 5 << 20]
            .iter()
            .map(|&b| format_bytes_short(b))
            .collect();
        assert_eq!(
            bytes,
            ["0B", "17B", "1023B", "1.0K", "3.0K", "10K", "1023K", "5.0M"]
        );
        let counts: Vec<String> = [9999, 10_000, 999_999, 1_250_000, 12_000_000]
            .iter()
            .map(|&n| format_count_short(n))
            .collect();
        assert_eq!(counts, ["9999", "10k", "999k", "1.2M", "12M"]);
        assert_eq!(format_pids_short(&[4194304]), "4194304    ");
        assert_eq!(format_pids_short(&[12, 13]), "     12,...");
    }
}
