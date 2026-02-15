use super::process_graph::ProcessGraph;
use crate::parser::{Addr2LineResolver, SummaryStats, SyscallEntry};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashSet;

pub const MAX_TREE_DEPTH: usize = 8;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeElement {
    Empty,      // No element (end of prefix)
    Space,      // Spacing for parent that is last (renders as "    ")
    Vertical,   // │ (parent has siblings) - renders as "│   "
    Branch,     // ├ (middle child) - renders as "├─ "
    LastBranch, // └ (last child) - renders as "└─ "
}

pub type TreePrefix = [TreeElement; MAX_TREE_DEPTH];

#[derive(Debug, Clone)]
pub enum DisplayLine {
    SyscallHeader {
        entry_idx: usize,
        is_hidden: bool,
        is_search_match: bool,
    },
    ArgumentsHeader {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    ArgumentLine {
        entry_idx: usize,
        arg_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    ReturnValue {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    Error {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    Duration {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    Signal {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    Exit {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    BacktraceHeader {
        entry_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    BacktraceFrame {
        entry_idx: usize,
        frame_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
    BacktraceResolved {
        entry_idx: usize,
        frame_idx: usize,
        tree_prefix: TreePrefix,
        is_search_match: bool,
    },
}

impl DisplayLine {
    fn entry_idx(&self) -> usize {
        match self {
            DisplayLine::SyscallHeader { entry_idx, .. } => *entry_idx,
            DisplayLine::ArgumentsHeader { entry_idx, .. } => *entry_idx,
            DisplayLine::ArgumentLine { entry_idx, .. } => *entry_idx,
            DisplayLine::ReturnValue { entry_idx, .. } => *entry_idx,
            DisplayLine::Error { entry_idx, .. } => *entry_idx,
            DisplayLine::Duration { entry_idx, .. } => *entry_idx,
            DisplayLine::Signal { entry_idx, .. } => *entry_idx,
            DisplayLine::Exit { entry_idx, .. } => *entry_idx,
            DisplayLine::BacktraceHeader { entry_idx, .. } => *entry_idx,
            DisplayLine::BacktraceFrame { entry_idx, .. } => *entry_idx,
            DisplayLine::BacktraceResolved { entry_idx, .. } => *entry_idx,
        }
    }
}

pub struct FilterModalState {
    pub syscall_list: Vec<(String, usize)>, // (syscall_name, count)
    pub selected_index: usize,
    pub scroll_offset: usize,
}

pub struct SearchState {
    pub active: bool,
    pub query: String,
    pub matches: Vec<usize>,      // Indices of matching display lines
    pub current_match_idx: usize, // Index into matches vec
    pub original_position: usize, // Position before search (for Esc)
    pub original_scroll: usize,   // Scroll offset before search
}

impl SearchState {
    fn new() -> Self {
        Self {
            active: false,
            query: String::new(),
            matches: Vec::new(),
            current_match_idx: 0,
            original_position: 0,
            original_scroll: 0,
        }
    }
}

pub struct App {
    // Data
    pub entries: Vec<SyscallEntry>,
    pub resolver: Addr2LineResolver,
    pub summary: SummaryStats,
    pub file_path: Option<String>,
    pub process_graph: ProcessGraph,

    // UI State
    pub display_lines: Vec<DisplayLine>,
    pub selected_line: usize,
    pub scroll_offset: usize,
    pub expanded_items: HashSet<usize>,
    pub expanded_arguments: HashSet<usize>,
    pub expanded_backtraces: HashSet<usize>,
    pub last_visible_height: usize, // Track for page scrolling
    pub last_collapsed_position: Option<usize>, // Remember position before collapse for right arrow
    pub last_collapsed_scroll: Option<usize>, // Remember scroll_offset before collapse

    // Filter state
    pub hidden_syscalls: HashSet<String>,
    pub show_hidden: bool,
    pub show_filter_modal: bool,
    pub filter_modal_state: FilterModalState,

    // Search state
    pub search_state: SearchState,
    pub modal_search_state: SearchState,

    // Flags
    pub should_quit: bool,
    pub show_help: bool,
}

impl App {
    pub fn new(
        entries: Vec<SyscallEntry>,
        summary: SummaryStats,
        file_path: Option<String>,
    ) -> Self {
        let process_graph = ProcessGraph::build(&entries);

        // Build syscall list for filter modal
        let mut syscall_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for entry in &entries {
            if !entry.syscall_name.is_empty() {
                *syscall_counts
                    .entry(entry.syscall_name.clone())
                    .or_insert(0) += 1;
            }
        }
        let mut syscall_list: Vec<(String, usize)> = syscall_counts.into_iter().collect();
        syscall_list.sort_by(|a, b| a.0.cmp(&b.0)); // Sort by name

        let mut app = Self {
            entries,
            resolver: Addr2LineResolver::new(),
            summary,
            file_path,
            process_graph,
            display_lines: Vec::new(),
            selected_line: 0,
            scroll_offset: 0,
            expanded_items: HashSet::new(),
            expanded_arguments: HashSet::new(),
            expanded_backtraces: HashSet::new(),
            last_visible_height: 20, // Default, will be updated on first draw
            last_collapsed_position: None,
            last_collapsed_scroll: None,
            hidden_syscalls: HashSet::new(),
            show_hidden: false,
            show_filter_modal: false,
            filter_modal_state: FilterModalState {
                syscall_list,
                selected_index: 0,
                scroll_offset: 0,
            },
            search_state: SearchState::new(),
            modal_search_state: SearchState::new(),
            should_quit: false,
            show_help: false,
        };
        app.rebuild_display_lines();
        app
    }

    pub fn update_visible_height(&mut self, height: usize) {
        self.last_visible_height = height;
    }

    /// Converts TreePrefix array to display string
    /// Each element renders to fixed-width string with spacing
    pub fn tree_prefix_to_string(prefix: &TreePrefix) -> String {
        let mut result = String::new();

        // Add leading indentation (2 spaces)
        result.push_str("  ");

        // Render each tree element
        for &elem in prefix.iter() {
            match elem {
                TreeElement::Empty => break,                       // End of prefix
                TreeElement::Space => result.push_str("    "), // 4 spaces for parent that is last
                TreeElement::Vertical => result.push_str("│   "), // Vertical + 3 spaces
                TreeElement::Branch => result.push_str("├─ "), // Branch + horizontal + space
                TreeElement::LastBranch => result.push_str("└─ "), // Last branch + horizontal + space
            }
        }

        result
    }

    /// Converts TreePrefix array to display string for headers (no horizontal line on last element)
    /// Headers need "├" or "└" without the horizontal to place arrow directly after
    pub fn tree_prefix_to_string_header(prefix: &TreePrefix) -> String {
        let mut result = String::new();

        // Add leading indentation (2 spaces)
        result.push_str("  ");

        // Render each tree element, but handle last one differently
        let mut last_idx = 0;
        for (idx, &elem) in prefix.iter().enumerate() {
            if elem == TreeElement::Empty {
                last_idx = idx;
                break;
            }
        }
        if last_idx == 0 {
            last_idx = MAX_TREE_DEPTH;
        }

        for (idx, &elem) in prefix.iter().enumerate() {
            match elem {
                TreeElement::Empty => break,
                TreeElement::Space => result.push_str("    "),
                TreeElement::Vertical => result.push_str("│   "),
                TreeElement::Branch => {
                    if idx == last_idx - 1 {
                        // Last element for header: just "├" without horizontal
                        result.push('├');
                    } else {
                        result.push_str("├─ ");
                    }
                }
                TreeElement::LastBranch => {
                    if idx == last_idx - 1 {
                        // Last element for header: just "└" without horizontal
                        result.push('└');
                    } else {
                        result.push_str("└─ ");
                    }
                }
            }
        }

        result
    }

    /// Builds tree prefix for a child item
    fn build_tree_prefix(parent_prefix: &TreePrefix, is_last_child: bool) -> TreePrefix {
        let mut prefix = *parent_prefix;

        // Find first empty slot
        let depth = prefix
            .iter()
            .position(|&e| e == TreeElement::Empty)
            .unwrap_or(MAX_TREE_DEPTH);

        if depth >= MAX_TREE_DEPTH {
            return prefix; // Max depth reached
        }

        // Add appropriate branch element (rendering adds horizontal + space)
        prefix[depth] = if is_last_child {
            TreeElement::LastBranch
        } else {
            TreeElement::Branch
        };

        prefix
    }

    /// Builds base prefix for nested children
    /// Replaces the parent's branch element with vertical/space continuation
    fn build_nested_prefix(parent_prefix: &TreePrefix, parent_is_last: bool) -> TreePrefix {
        let mut prefix = *parent_prefix;

        // Find the parent's branch element (the last non-Empty element)
        let mut parent_branch_idx = None;
        for (idx, &elem) in prefix.iter().enumerate() {
            if elem == TreeElement::Empty {
                if idx > 0 {
                    parent_branch_idx = Some(idx - 1);
                }
                break;
            }
        }

        if let Some(idx) = parent_branch_idx {
            // Replace parent's Branch/LastBranch with Vertical or Space
            if !parent_is_last {
                // Parent has siblings after, use vertical line (renders as "│   ")
                prefix[idx] = TreeElement::Vertical;
            } else {
                // Parent is last, use spaces (rendering adds 4 spaces)
                prefix[idx] = TreeElement::Space;
            }
        }

        prefix
    }

    fn rebuild_display_lines(&mut self) {
        // Remember which entry we're looking at before rebuilding
        let current_entry_idx = if self.selected_line < self.display_lines.len() {
            Some(self.display_lines[self.selected_line].entry_idx())
        } else {
            None
        };

        self.display_lines.clear();

        for (idx, entry) in self.entries.iter().enumerate() {
            // Check if this syscall should be hidden
            let is_hidden = self.hidden_syscalls.contains(&entry.syscall_name);

            // Skip hidden items unless show_hidden is true
            if is_hidden && !self.show_hidden {
                continue;
            }

            // Always add the syscall header
            self.display_lines.push(DisplayLine::SyscallHeader {
                entry_idx: idx,
                is_hidden,
                is_search_match: false,
            });

            // Add expanded details if item is expanded
            if self.expanded_items.contains(&idx) {
                // Collect all top-level items to determine which is last
                let has_arguments = !entry.arguments.is_empty();
                let has_return = entry.return_value.is_some();
                let has_error = entry.errno.is_some();
                let has_duration = entry.duration.is_some();
                let has_signal = entry.signal.is_some();
                let has_exit = entry.exit_info.is_some();
                let has_backtrace = !entry.backtrace.is_empty();

                let mut items = Vec::new();
                if has_arguments {
                    items.push("arguments");
                }
                if has_return {
                    items.push("return");
                }
                if has_error {
                    items.push("error");
                }
                if has_duration {
                    items.push("duration");
                }
                if has_signal {
                    items.push("signal");
                }
                if has_exit {
                    items.push("exit");
                }
                if has_backtrace {
                    items.push("backtrace");
                }

                let total_items = items.len();

                // Base prefix: empty (leading spaces added during rendering)
                let base_prefix: TreePrefix = [TreeElement::Empty; MAX_TREE_DEPTH];
                let mut item_idx = 0;

                // Arguments
                if has_arguments {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);

                    self.display_lines.push(DisplayLine::ArgumentsHeader {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });

                    // Add arguments if expanded
                    if self.expanded_arguments.contains(&idx) {
                        let args = split_arguments(&entry.arguments);
                        let nested_base = Self::build_nested_prefix(&prefix, is_last);

                        for (arg_idx, _arg) in args.iter().enumerate() {
                            let is_last_arg = arg_idx == args.len() - 1;
                            let arg_prefix = Self::build_tree_prefix(&nested_base, is_last_arg);

                            self.display_lines.push(DisplayLine::ArgumentLine {
                                entry_idx: idx,
                                arg_idx,
                                tree_prefix: arg_prefix,
                                is_search_match: false,
                            });
                        }
                    }
                    item_idx += 1;
                }

                // Return value
                if has_return {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);
                    self.display_lines.push(DisplayLine::ReturnValue {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });
                    item_idx += 1;
                }

                // Error
                if has_error {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);
                    self.display_lines.push(DisplayLine::Error {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });
                    item_idx += 1;
                }

                // Duration
                if has_duration {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);
                    self.display_lines.push(DisplayLine::Duration {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });
                    item_idx += 1;
                }

                // Signal
                if has_signal {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);
                    self.display_lines.push(DisplayLine::Signal {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });
                    item_idx += 1;
                }

                // Exit
                if has_exit {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);
                    self.display_lines.push(DisplayLine::Exit {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });
                    item_idx += 1;
                }

                // Backtrace
                if has_backtrace {
                    let is_last = item_idx == total_items - 1;
                    let prefix = Self::build_tree_prefix(&base_prefix, is_last);

                    self.display_lines.push(DisplayLine::BacktraceHeader {
                        entry_idx: idx,
                        tree_prefix: prefix,
                        is_search_match: false,
                    });

                    // Add backtrace frames if expanded
                    if self.expanded_backtraces.contains(&idx) {
                        let nested_base = Self::build_nested_prefix(&prefix, is_last);

                        for (frame_idx, frame) in entry.backtrace.iter().enumerate() {
                            let is_last_frame = frame_idx == entry.backtrace.len() - 1;
                            let frame_prefix = Self::build_tree_prefix(&nested_base, is_last_frame);

                            if frame.resolved.is_none() {
                                self.display_lines.push(DisplayLine::BacktraceFrame {
                                    entry_idx: idx,
                                    frame_idx,
                                    tree_prefix: frame_prefix,
                                    is_search_match: false,
                                });
                            } else {
                                self.display_lines.push(DisplayLine::BacktraceResolved {
                                    entry_idx: idx,
                                    frame_idx,
                                    tree_prefix: frame_prefix,
                                    is_search_match: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Clamp selection to valid range
        if self.selected_line >= self.display_lines.len() && !self.display_lines.is_empty() {
            self.selected_line = self.display_lines.len() - 1;
        }

        // Update search matches if search is active (without moving cursor)
        if !self.search_state.matches.is_empty() {
            self.update_search_matches_internal(false);
        }
    }

    pub fn handle_event(&mut self, event: KeyEvent) {
        // Priority 1: Search mode
        if self.search_state.active {
            self.handle_search_event(event);
            return;
        }

        // Priority 2: Filter modal
        if self.show_filter_modal {
            self.handle_filter_modal_event(event);
            return;
        }

        // Priority 3: Help screen
        if self.show_help {
            if matches!(event.code, KeyCode::Char('?') | KeyCode::Esc) {
                self.show_help = false;
            }
            return;
        }

        match event.code {
            // Quit
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.should_quit = true;
            }
            KeyCode::Char('c') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }

            // Help
            KeyCode::Char('?') => {
                self.show_help = true;
            }

            // Filter controls
            KeyCode::Char('h') => {
                self.toggle_current_syscall_visibility();
            }
            KeyCode::Char('H') => {
                self.open_filter_modal();
            }
            KeyCode::Char('.') => {
                self.toggle_show_hidden();
            }

            // Navigation
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_up();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_down();
            }
            KeyCode::PageUp => {
                self.scroll_page(true, false);
            }
            KeyCode::PageDown => {
                self.scroll_page(false, false);
            }
            KeyCode::Char('u') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.scroll_page(true, true);
            }
            KeyCode::Char('d') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.scroll_page(false, true);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.selected_line = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                if !self.display_lines.is_empty() {
                    self.selected_line = self.display_lines.len() - 1;
                }
            }

            // Expand/Collapse
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.toggle_current_line();
            }
            KeyCode::Left => {
                self.collapse_deepest();
            }
            KeyCode::Right => {
                self.expand_current();
            }
            KeyCode::Backspace | KeyCode::Char('x') => {
                self.collapse_current();
            }
            KeyCode::Char('e') => {
                self.expand_all();
            }
            KeyCode::Char('c') if !event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.collapse_all();
            }
            KeyCode::Char('r') => {
                self.resolve_current_backtrace();
            }
            KeyCode::Char('R') => {
                self.resolve_all_backtraces();
            }

            // Search controls
            KeyCode::Char('/') => {
                self.start_search();
            }
            KeyCode::Char('n') if !self.search_state.query.is_empty() => {
                self.search_next();
            }
            KeyCode::Char('N') if !self.search_state.query.is_empty() => {
                self.search_previous();
            }

            _ => {}
        }
    }

    fn move_up(&mut self) {
        self.last_collapsed_position = None; // Clear memory on navigation
        self.last_collapsed_scroll = None;
        if self.selected_line > 0 {
            self.selected_line -= 1;
        }
    }

    fn move_down(&mut self) {
        self.last_collapsed_position = None; // Clear memory on navigation
        self.last_collapsed_scroll = None;
        if self.selected_line + 1 < self.display_lines.len() {
            self.selected_line += 1;
        }
    }

    fn scroll_page(&mut self, up: bool, half: bool) {
        if self.display_lines.is_empty() {
            return;
        }

        // Calculate scroll amount
        let page_size = if half {
            self.last_visible_height / 2
        } else {
            self.last_visible_height
        };

        if up {
            // Scroll up
            let scroll_amount = page_size.min(self.scroll_offset);
            self.scroll_offset = self.scroll_offset.saturating_sub(scroll_amount);
            self.selected_line = self.selected_line.saturating_sub(scroll_amount);
        } else {
            // Scroll down
            let max_scroll = self
                .display_lines
                .len()
                .saturating_sub(self.last_visible_height);
            let scroll_amount = page_size.min(max_scroll.saturating_sub(self.scroll_offset));
            self.scroll_offset = (self.scroll_offset + scroll_amount).min(max_scroll);
            self.selected_line = (self.selected_line + scroll_amount)
                .min(self.display_lines.len().saturating_sub(1));
        }

        // Try to maintain cursor position on screen
        // Clamp selected_line to visible range
        let min_visible = self.scroll_offset;
        let max_visible = (self.scroll_offset + self.last_visible_height)
            .min(self.display_lines.len())
            .saturating_sub(1);

        if self.selected_line < min_visible {
            self.selected_line = min_visible;
        } else if self.selected_line > max_visible {
            self.selected_line = max_visible;
        }
    }

    fn adjust_scroll_after_expansion(&mut self, header_line: usize) {
        // Find the last line of the expanded item
        let entry_idx = self.display_lines[header_line].entry_idx();

        // Find the last line that belongs to this entry
        let last_line = self
            .display_lines
            .iter()
            .enumerate()
            .rev()
            .find(|(_, line)| line.entry_idx() == entry_idx)
            .map(|(idx, _)| idx)
            .unwrap_or(header_line);

        // Check if last_line is below the bottom of the screen
        let visible_bottom = self.scroll_offset + self.last_visible_height;

        if last_line + 1 > visible_bottom {
            // Need to scroll down to show the entire expanded item

            // Calculate how much we need to scroll to show last_line with 2-line gap
            let desired_bottom = last_line + 3; // last_line + 2 gap lines + 1 for indexing
            let needed_scroll = desired_bottom.saturating_sub(self.last_visible_height);

            // But don't scroll so far that header_line goes above 2 lines from top
            let max_scroll = header_line.saturating_sub(2);

            // Also respect the maximum possible scroll
            let max_possible_scroll = self
                .display_lines
                .len()
                .saturating_sub(self.last_visible_height);

            // Use the minimum of all constraints
            self.scroll_offset = needed_scroll.min(max_scroll).min(max_possible_scroll);
        }
    }

    fn toggle_current_line(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx, .. } => {
                // Toggle syscall expansion
                let idx = *entry_idx;
                if self.expanded_items.contains(&idx) {
                    log::debug!("Collapsing syscall {}", idx);
                    self.expanded_items.remove(&idx);
                    self.expanded_backtraces.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!(
                        "Expanding syscall {}, saving scroll_offset={}",
                        idx,
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;

                    self.expanded_items.insert(idx);
                    self.rebuild_display_lines();

                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expansion adjustment, scroll_offset={}",
                        self.scroll_offset
                    );
                    return;
                }
                self.rebuild_display_lines();
            }
            DisplayLine::BacktraceHeader { entry_idx, .. } => {
                // Toggle backtrace expansion
                let idx = *entry_idx;
                if self.expanded_backtraces.contains(&idx) {
                    log::debug!("Collapsing backtrace {}", idx);
                    self.expanded_backtraces.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!(
                        "Expanding backtrace {}, saving scroll_offset={}",
                        idx,
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;

                    self.expanded_backtraces.insert(idx);
                    // Resolve on-demand
                    if let Some(entry) = self.entries.get_mut(idx)
                        && !entry.backtrace.is_empty()
                    {
                        let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                    }
                    self.rebuild_display_lines();

                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expansion adjustment, scroll_offset={}",
                        self.scroll_offset
                    );
                    return;
                }
                self.rebuild_display_lines();
            }
            DisplayLine::ArgumentsHeader { entry_idx, .. } => {
                // Toggle arguments expansion
                let idx = *entry_idx;
                if self.expanded_arguments.contains(&idx) {
                    log::debug!("Collapsing arguments {}", idx);
                    self.expanded_arguments.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!(
                        "Expanding arguments {}, saving scroll_offset={}",
                        idx,
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;

                    self.expanded_arguments.insert(idx);
                    self.rebuild_display_lines();

                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expansion adjustment, scroll_offset={}",
                        self.scroll_offset
                    );
                    return;
                }
                self.rebuild_display_lines();
            }
            _ => {
                // For other line types, do nothing on Enter
            }
        }
    }

    fn expand_current(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        let saved_position = self.last_collapsed_position;

        log::debug!(
            "expand_current: selected_line={}, saved_position={:?}",
            self.selected_line,
            saved_position
        );

        match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx, .. } => {
                // Expand syscall if not already expanded
                let idx = *entry_idx;
                if !self.expanded_items.contains(&idx) {
                    log::debug!("Expanding syscall {}", idx);
                    let header_line = self.selected_line;

                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!(
                        "Saving scroll_offset={} for future collapse",
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);

                    self.expanded_items.insert(idx);
                    self.rebuild_display_lines();

                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position
                        && saved_line < self.display_lines.len()
                    {
                        log::debug!("Restoring cursor position to {}", saved_line);
                        self.selected_line = saved_line;
                    }

                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expand_current (syscall), scroll_offset={}",
                        self.scroll_offset
                    );
                }
            }
            DisplayLine::ArgumentsHeader { entry_idx, .. } => {
                // Expand arguments if not already expanded
                let idx = *entry_idx;
                if !self.expanded_arguments.contains(&idx) {
                    log::debug!("Expanding arguments {}", idx);
                    let header_line = self.selected_line;

                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!(
                        "Saving scroll_offset={} for future collapse",
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);

                    self.expanded_arguments.insert(idx);
                    self.rebuild_display_lines();

                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position
                        && saved_line < self.display_lines.len()
                    {
                        log::debug!("Restoring cursor position to {}", saved_line);
                        self.selected_line = saved_line;
                    }

                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expand_current (arguments), scroll_offset={}",
                        self.scroll_offset
                    );
                }
            }
            DisplayLine::BacktraceHeader { entry_idx, .. } => {
                // Expand backtrace if not already expanded
                let idx = *entry_idx;
                if !self.expanded_backtraces.contains(&idx) {
                    log::debug!("Expanding backtrace {}", idx);
                    let header_line = self.selected_line;

                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!(
                        "Saving scroll_offset={} for future collapse",
                        self.scroll_offset
                    );
                    self.last_collapsed_scroll = Some(self.scroll_offset);

                    self.expanded_backtraces.insert(idx);
                    // Resolve on-demand
                    if let Some(entry) = self.entries.get_mut(idx)
                        && !entry.backtrace.is_empty()
                    {
                        let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                    }
                    self.rebuild_display_lines();

                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position
                        && saved_line < self.display_lines.len()
                    {
                        log::debug!("Restoring cursor position to {}", saved_line);
                        self.selected_line = saved_line;
                    }

                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!(
                        "After expand_current (backtrace), scroll_offset={}",
                        self.scroll_offset
                    );
                }
            }
            _ => {
                // For other line types, do nothing
            }
        }

        // Only clear saved position if we used it (restored cursor)
        if saved_position.is_some() {
            log::debug!("Clearing saved position after restore");
            self.last_collapsed_position = None;
        }
        // Keep last_collapsed_scroll for the next collapse
    }

    fn collapse_deepest(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        log::debug!(
            "collapse_deepest: selected_line={}, scroll_offset={}, last_collapsed_scroll={:?}",
            self.selected_line,
            self.scroll_offset,
            self.last_collapsed_scroll
        );

        // Save current position for potential re-expansion with right arrow
        let saved_position = Some(self.selected_line);

        // Get the saved scroll from before expansion (to restore it)
        let scroll_to_restore = self.last_collapsed_scroll;

        // Collapse the deepest surrounding fold based on current line type
        match &self.display_lines[self.selected_line] {
            DisplayLine::ArgumentLine { entry_idx, .. } => {
                // In an argument line -> collapse arguments
                let idx = *entry_idx;
                log::debug!("Collapsing arguments {} from ArgumentLine", idx);
                self.expanded_arguments.remove(&idx);
                self.rebuild_display_lines();

                // Move cursor to ArgumentsHeader
                self.selected_line = self.display_lines.iter()
                    .position(|line| matches!(line, DisplayLine::ArgumentsHeader { entry_idx: i, .. } if *i == idx))
                    .unwrap_or(self.selected_line);
            }
            DisplayLine::BacktraceFrame { entry_idx, .. }
            | DisplayLine::BacktraceResolved { entry_idx, .. } => {
                // In a backtrace frame -> collapse backtrace
                let idx = *entry_idx;
                self.expanded_backtraces.remove(&idx);
                self.rebuild_display_lines();

                // Move cursor to BacktraceHeader
                self.selected_line = self.display_lines.iter()
                    .position(|line| matches!(line, DisplayLine::BacktraceHeader { entry_idx: i, .. } if *i == idx))
                    .unwrap_or(self.selected_line);
            }
            DisplayLine::ArgumentsHeader { entry_idx, .. } => {
                // On arguments header -> collapse arguments if expanded, else collapse syscall
                let idx = *entry_idx;
                if self.expanded_arguments.contains(&idx) {
                    log::debug!("Collapsing arguments {} from ArgumentsHeader", idx);
                    self.expanded_arguments.remove(&idx);
                    self.rebuild_display_lines();
                    // Already on header, no need to move
                } else {
                    // Arguments already collapsed, collapse the parent syscall
                    log::debug!(
                        "Arguments {} already collapsed, collapsing parent syscall",
                        idx
                    );
                    self.expanded_items.remove(&idx);
                    self.expanded_arguments.remove(&idx);
                    self.expanded_backtraces.remove(&idx);
                    self.rebuild_display_lines();

                    // Move cursor to SyscallHeader
                    self.selected_line = self.display_lines.iter()
                        .position(|line| matches!(line, DisplayLine::SyscallHeader { entry_idx: i, .. } if *i == idx))
                        .unwrap_or(self.selected_line);
                }
            }
            DisplayLine::BacktraceHeader { entry_idx, .. } => {
                // On backtrace header -> collapse backtrace if expanded, else collapse syscall
                let idx = *entry_idx;
                if self.expanded_backtraces.contains(&idx) {
                    log::debug!("Collapsing backtrace {} from BacktraceHeader", idx);
                    self.expanded_backtraces.remove(&idx);
                    self.rebuild_display_lines();
                    // Already on header, no need to move
                } else {
                    // Backtrace already collapsed, collapse the parent syscall
                    log::debug!(
                        "Backtrace {} already collapsed, collapsing parent syscall",
                        idx
                    );
                    self.expanded_items.remove(&idx);
                    self.expanded_arguments.remove(&idx);
                    self.expanded_backtraces.remove(&idx);
                    self.rebuild_display_lines();

                    // Move cursor to SyscallHeader
                    self.selected_line = self.display_lines.iter()
                        .position(|line| matches!(line, DisplayLine::SyscallHeader { entry_idx: i, .. } if *i == idx))
                        .unwrap_or(self.selected_line);
                }
            }
            DisplayLine::SyscallHeader { entry_idx, .. }
            | DisplayLine::ReturnValue { entry_idx, .. }
            | DisplayLine::Error { entry_idx, .. }
            | DisplayLine::Duration { entry_idx, .. }
            | DisplayLine::Signal { entry_idx, .. }
            | DisplayLine::Exit { entry_idx, .. } => {
                // On syscall header or other top-level items -> collapse entire syscall
                let idx = *entry_idx;
                self.expanded_items.remove(&idx);
                self.expanded_arguments.remove(&idx);
                self.expanded_backtraces.remove(&idx);
                self.rebuild_display_lines();

                // Move cursor to SyscallHeader
                self.selected_line = self.display_lines.iter()
                    .position(|line| matches!(line, DisplayLine::SyscallHeader { entry_idx: i, .. } if *i == idx))
                    .unwrap_or(self.selected_line);
            }
        }

        // Restore the scroll position from before expansion
        if let Some(scroll) = scroll_to_restore {
            log::debug!(
                "Restoring scroll_offset from {} to {}",
                self.scroll_offset,
                scroll
            );
            self.scroll_offset = scroll;
        } else {
            log::debug!("No saved scroll to restore");
        }

        // Save position for potential re-expansion with right arrow
        self.last_collapsed_position = saved_position;
        // Keep the scroll saved for re-expansion (don't change last_collapsed_scroll)
    }

    fn collapse_current(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        // Find the entry_idx of the current line and collapse it
        let entry_idx = match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ArgumentsHeader { entry_idx, .. } => {
                // For arguments header, collapse just the arguments
                let idx = *entry_idx;
                self.expanded_arguments.remove(&idx);
                self.rebuild_display_lines();
                return;
            }
            DisplayLine::ArgumentLine { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ReturnValue { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Error { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Duration { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Signal { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Exit { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceHeader { entry_idx, .. } => {
                // For backtrace header, collapse just the backtrace
                let idx = *entry_idx;
                self.expanded_backtraces.remove(&idx);
                self.rebuild_display_lines();
                return;
            }
            DisplayLine::BacktraceFrame { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceResolved { entry_idx, .. } => Some(*entry_idx),
        };

        if let Some(idx) = entry_idx {
            self.expanded_items.remove(&idx);
            self.expanded_arguments.remove(&idx);
            self.expanded_backtraces.remove(&idx);
            self.rebuild_display_lines();
        }
    }

    fn expand_all(&mut self) {
        // Remember which entry we're currently on and cursor position on screen
        let current_entry_idx = if self.selected_line < self.display_lines.len() {
            Some(self.display_lines[self.selected_line].entry_idx())
        } else {
            None
        };
        let cursor_screen_pos = self.selected_line.saturating_sub(self.scroll_offset);

        for i in 0..self.entries.len() {
            self.expanded_items.insert(i);
        }
        self.rebuild_display_lines();

        // Restore cursor to the same entry
        if let Some(entry_idx) = current_entry_idx {
            self.selected_line = self
                .display_lines
                .iter()
                .position(|line| line.entry_idx() == entry_idx)
                .unwrap_or(0);

            // Restore cursor screen position
            self.scroll_offset = self.selected_line.saturating_sub(cursor_screen_pos);
        }
    }

    fn collapse_all(&mut self) {
        // Remember which entry we're currently on and cursor position on screen
        let current_entry_idx = if self.selected_line < self.display_lines.len() {
            Some(self.display_lines[self.selected_line].entry_idx())
        } else {
            None
        };
        let cursor_screen_pos = self.selected_line.saturating_sub(self.scroll_offset);

        self.expanded_items.clear();
        self.expanded_arguments.clear();
        self.expanded_backtraces.clear();
        self.rebuild_display_lines();

        // Restore cursor to the same entry (should be header line)
        if let Some(entry_idx) = current_entry_idx {
            self.selected_line = self
                .display_lines
                .iter()
                .position(|line| line.entry_idx() == entry_idx)
                .unwrap_or(0);

            // Restore cursor screen position
            self.scroll_offset = self.selected_line.saturating_sub(cursor_screen_pos);
        }
    }

    // Filter management methods
    pub fn toggle_current_syscall_visibility(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        let entry_idx = self.display_lines[self.selected_line].entry_idx();
        if let Some(entry) = self.entries.get(entry_idx) {
            let syscall_name = entry.syscall_name.clone();
            if self.hidden_syscalls.contains(&syscall_name) {
                self.hidden_syscalls.remove(&syscall_name);
            } else {
                self.hidden_syscalls.insert(syscall_name);
            }
            self.rebuild_display_lines();

            // Adjust selection if current line is now hidden
            if self.selected_line >= self.display_lines.len() && !self.display_lines.is_empty() {
                self.selected_line = self.display_lines.len() - 1;
            }
        }
    }

    pub fn toggle_show_hidden(&mut self) {
        self.show_hidden = !self.show_hidden;
        self.rebuild_display_lines();
    }

    pub fn open_filter_modal(&mut self) {
        self.show_filter_modal = true;
        self.filter_modal_state.selected_index = 0;
        self.filter_modal_state.scroll_offset = 0;
    }

    pub fn close_filter_modal(&mut self) {
        self.show_filter_modal = false;
    }

    pub fn toggle_all_syscalls(&mut self) {
        if self.hidden_syscalls.is_empty() {
            // Hide all
            for (syscall_name, _) in &self.filter_modal_state.syscall_list {
                self.hidden_syscalls.insert(syscall_name.clone());
            }
        } else {
            // Show all
            self.hidden_syscalls.clear();
        }
        self.rebuild_display_lines();
    }

    pub fn handle_filter_modal_event(&mut self, event: KeyEvent) {
        // Get visible height for scroll calculations (estimate based on typical modal size)
        // The modal takes 70% of screen height, minus 2 for borders
        let visible_height = (self.last_visible_height * 70 / 100).saturating_sub(2);

        match event.code {
            KeyCode::Esc | KeyCode::Char('H') | KeyCode::Char('q') => {
                self.close_filter_modal();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.filter_modal_state.selected_index > 0 {
                    self.filter_modal_state.selected_index -= 1;

                    // Adjust scroll if needed
                    if self.filter_modal_state.selected_index
                        < self.filter_modal_state.scroll_offset
                    {
                        self.filter_modal_state.scroll_offset =
                            self.filter_modal_state.selected_index;
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.filter_modal_state.selected_index + 1
                    < self.filter_modal_state.syscall_list.len()
                {
                    self.filter_modal_state.selected_index += 1;

                    // Adjust scroll if needed
                    let max_visible = self.filter_modal_state.scroll_offset + visible_height;
                    if self.filter_modal_state.selected_index >= max_visible {
                        self.filter_modal_state.scroll_offset = self
                            .filter_modal_state
                            .selected_index
                            .saturating_sub(visible_height)
                            + 1;
                    }
                }
            }
            KeyCode::PageUp => {
                let scroll_amount = visible_height;
                self.filter_modal_state.selected_index = self
                    .filter_modal_state
                    .selected_index
                    .saturating_sub(scroll_amount);
                self.filter_modal_state.scroll_offset = self
                    .filter_modal_state
                    .scroll_offset
                    .saturating_sub(scroll_amount);
            }
            KeyCode::PageDown => {
                let scroll_amount = visible_height;
                let max_index = self.filter_modal_state.syscall_list.len().saturating_sub(1);
                self.filter_modal_state.selected_index =
                    (self.filter_modal_state.selected_index + scroll_amount).min(max_index);

                let max_scroll = self
                    .filter_modal_state
                    .syscall_list
                    .len()
                    .saturating_sub(visible_height);
                self.filter_modal_state.scroll_offset =
                    (self.filter_modal_state.scroll_offset + scroll_amount).min(max_scroll);
            }
            KeyCode::Char('u') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                let scroll_amount = visible_height / 2;
                self.filter_modal_state.selected_index = self
                    .filter_modal_state
                    .selected_index
                    .saturating_sub(scroll_amount);
                self.filter_modal_state.scroll_offset = self
                    .filter_modal_state
                    .scroll_offset
                    .saturating_sub(scroll_amount);
            }
            KeyCode::Char('d') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                let scroll_amount = visible_height / 2;
                let max_index = self.filter_modal_state.syscall_list.len().saturating_sub(1);
                self.filter_modal_state.selected_index =
                    (self.filter_modal_state.selected_index + scroll_amount).min(max_index);

                let max_scroll = self
                    .filter_modal_state
                    .syscall_list
                    .len()
                    .saturating_sub(visible_height);
                self.filter_modal_state.scroll_offset =
                    (self.filter_modal_state.scroll_offset + scroll_amount).min(max_scroll);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.filter_modal_state.selected_index = 0;
                self.filter_modal_state.scroll_offset = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                let max_index = self.filter_modal_state.syscall_list.len().saturating_sub(1);
                self.filter_modal_state.selected_index = max_index;

                let max_scroll = self
                    .filter_modal_state
                    .syscall_list
                    .len()
                    .saturating_sub(visible_height);
                self.filter_modal_state.scroll_offset = max_scroll;
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
                // Toggle the selected syscall
                if let Some((syscall_name, _)) = self
                    .filter_modal_state
                    .syscall_list
                    .get(self.filter_modal_state.selected_index)
                {
                    let syscall_name = syscall_name.clone();
                    if self.hidden_syscalls.contains(&syscall_name) {
                        self.hidden_syscalls.remove(&syscall_name);
                    } else {
                        self.hidden_syscalls.insert(syscall_name);
                    }
                    self.rebuild_display_lines();
                }
            }
            KeyCode::Char('a') => {
                self.toggle_all_syscalls();
            }
            _ => {}
        }
    }

    // Search methods
    pub fn start_search(&mut self) {
        self.search_state.active = true;
        self.search_state.original_position = self.selected_line;
        self.search_state.original_scroll = self.scroll_offset;
        self.search_state.query.clear();
        self.search_state.matches.clear();
        self.search_state.current_match_idx = 0;
    }

    pub fn start_modal_search(&mut self) {
        self.modal_search_state.active = true;
        self.modal_search_state.original_position = self.filter_modal_state.selected_index;
        self.modal_search_state.original_scroll = self.filter_modal_state.scroll_offset;
        self.modal_search_state.query.clear();
        self.modal_search_state.matches.clear();
        self.modal_search_state.current_match_idx = 0;
    }

    fn get_line_text(&self, line: &DisplayLine) -> String {
        match line {
            DisplayLine::SyscallHeader { entry_idx, .. } => {
                let entry = &self.entries[*entry_idx];
                format!(
                    "{} {} {}",
                    entry.syscall_name,
                    entry.arguments,
                    entry.return_value.as_deref().unwrap_or("")
                )
            }
            DisplayLine::ArgumentLine {
                entry_idx, arg_idx, ..
            } => {
                let entry = &self.entries[*entry_idx];
                let args = split_arguments(&entry.arguments);
                args.get(*arg_idx).cloned().unwrap_or_default()
            }
            DisplayLine::ArgumentsHeader { .. } => "Arguments".to_string(),
            DisplayLine::ReturnValue { entry_idx, .. } => {
                let entry = &self.entries[*entry_idx];
                format!("Return: {}", entry.return_value.as_deref().unwrap_or("?"))
            }
            DisplayLine::Error { entry_idx, .. } => {
                let entry = &self.entries[*entry_idx];
                if let Some(errno) = &entry.errno {
                    format!("Error: {} {}", errno.code, errno.message)
                } else {
                    String::new()
                }
            }
            DisplayLine::Signal { entry_idx, .. } => {
                let entry = &self.entries[*entry_idx];
                if let Some(signal) = &entry.signal {
                    format!("Signal: {}", signal.signal_name)
                } else {
                    String::new()
                }
            }
            DisplayLine::Exit { entry_idx, .. } => {
                let entry = &self.entries[*entry_idx];
                if let Some(exit) = &entry.exit_info {
                    format!("Exit: code={} killed={}", exit.code, exit.killed)
                } else {
                    String::new()
                }
            }
            DisplayLine::BacktraceHeader { .. } => "Backtrace".to_string(),
            DisplayLine::BacktraceFrame {
                entry_idx,
                frame_idx,
                ..
            } => {
                let entry = &self.entries[*entry_idx];
                if let Some(frame) = entry.backtrace.get(*frame_idx) {
                    format!("{} {}", frame.binary, frame.address)
                } else {
                    String::new()
                }
            }
            DisplayLine::BacktraceResolved {
                entry_idx,
                frame_idx,
                ..
            } => {
                let entry = &self.entries[*entry_idx];
                if let Some(frame) = entry.backtrace.get(*frame_idx) {
                    if let Some(resolved) = &frame.resolved {
                        format!("{} {}:{}", frame.binary, resolved.file, resolved.line)
                    } else {
                        format!("{} {}", frame.binary, frame.address)
                    }
                } else {
                    String::new()
                }
            }
            DisplayLine::Duration { .. } => String::new(),
        }
    }

    pub fn update_search_matches(&mut self) {
        self.update_search_matches_internal(true);
    }

    fn update_search_matches_internal(&mut self, move_cursor: bool) {
        log::debug!(
            "Updating search matches for query '{}'",
            self.search_state.query
        );
        self.search_state.matches.clear();

        if self.search_state.query.is_empty() {
            // Clear search match flags
            for line in &mut self.display_lines {
                match line {
                    DisplayLine::SyscallHeader {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::ArgumentsHeader {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::ArgumentLine {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::ReturnValue {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::Error {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::Duration {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::Signal {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::Exit {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::BacktraceHeader {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::BacktraceFrame {
                        is_search_match, ..
                    } => *is_search_match = false,
                    DisplayLine::BacktraceResolved {
                        is_search_match, ..
                    } => *is_search_match = false,
                }
            }
            return;
        }

        let query_lower = self.search_state.query.to_lowercase();

        // First pass: collect match information
        let mut matches_and_texts: Vec<(usize, bool)> = Vec::new();
        for (idx, line) in self.display_lines.iter().enumerate() {
            let text = self.get_line_text(line);
            let is_match = text.to_lowercase().contains(&query_lower);
            matches_and_texts.push((idx, is_match));
        }

        // Second pass: mark matches
        for (idx, is_match) in matches_and_texts {
            match &mut self.display_lines[idx] {
                DisplayLine::SyscallHeader {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::ArgumentsHeader {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::ArgumentLine {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::ReturnValue {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::Error {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::Duration {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::Signal {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::Exit {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::BacktraceHeader {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::BacktraceFrame {
                    is_search_match, ..
                } => *is_search_match = is_match,
                DisplayLine::BacktraceResolved {
                    is_search_match, ..
                } => *is_search_match = is_match,
            }

            if is_match {
                self.search_state.matches.push(idx);
            }
        }

        // Update current_match_idx to point to nearest match
        if !self.search_state.matches.is_empty() {
            // Find first match at or after current position
            let match_idx = self
                .search_state
                .matches
                .iter()
                .position(|&idx| idx >= self.selected_line)
                .unwrap_or(0); // Wrap to first if no match after cursor

            self.search_state.current_match_idx = match_idx;

            if move_cursor {
                log::debug!(
                    "Moving cursor to first match at line {}",
                    self.search_state.matches[match_idx]
                );
                self.selected_line = self.search_state.matches[match_idx];
                self.ensure_visible();
            }
        }
    }

    pub fn search_next(&mut self) {
        if self.search_state.matches.is_empty() {
            return;
        }

        // Find first match AFTER current cursor position
        let next_match = self
            .search_state
            .matches
            .iter()
            .position(|&idx| idx > self.selected_line);

        if let Some(match_idx) = next_match {
            // Found a match after cursor
            self.search_state.current_match_idx = match_idx;
        } else {
            // Wrap to first match
            self.search_state.current_match_idx = 0;
        }

        let match_line = self.search_state.matches[self.search_state.current_match_idx];
        self.selected_line = match_line;
        self.ensure_visible();
    }

    pub fn search_previous(&mut self) {
        if self.search_state.matches.is_empty() {
            return;
        }

        // Find last match BEFORE current cursor position
        let prev_match = self
            .search_state
            .matches
            .iter()
            .rposition(|&idx| idx < self.selected_line);

        if let Some(match_idx) = prev_match {
            // Found a match before cursor
            self.search_state.current_match_idx = match_idx;
        } else {
            // Wrap to last match
            self.search_state.current_match_idx = self.search_state.matches.len() - 1;
        }

        let match_line = self.search_state.matches[self.search_state.current_match_idx];
        self.selected_line = match_line;
        self.ensure_visible();
    }

    fn ensure_visible(&mut self) {
        if self.selected_line < self.scroll_offset {
            self.scroll_offset = self.selected_line;
        } else if self.selected_line >= self.scroll_offset + self.last_visible_height {
            self.scroll_offset = self.selected_line.saturating_sub(self.last_visible_height) + 1;
        }
    }

    pub fn handle_search_event(&mut self, event: KeyEvent) {
        match event.code {
            KeyCode::Char(c) if !event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search_state.query.push(c);
                self.update_search_matches();
            }
            KeyCode::Backspace => {
                self.search_state.query.pop();
                self.update_search_matches();
            }
            KeyCode::Enter => {
                // Accept search, stay at current position
                self.search_state.active = false;
            }
            KeyCode::Esc => {
                // Cancel search, return to original position
                self.selected_line = self.search_state.original_position;
                self.scroll_offset = self.search_state.original_scroll;
                self.search_state.active = false;
                self.search_state.query.clear();
                self.update_search_matches(); // Clear highlights
            }
            KeyCode::Char('n') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search_next();
            }
            KeyCode::Char('p') if event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.search_previous();
            }
            _ => {}
        }
    }

    fn resolve_current_backtrace(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }

        // Find the entry_idx from the current line
        let entry_idx = match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ArgumentsHeader { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ArgumentLine { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ReturnValue { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Error { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Duration { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Signal { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::Exit { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceHeader { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceFrame { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceResolved { entry_idx, .. } => Some(*entry_idx),
        };

        if let Some(idx) = entry_idx
            && let Some(entry) = self.entries.get_mut(idx)
            && !entry.backtrace.is_empty()
        {
            let _ = self.resolver.resolve_frames(&mut entry.backtrace);
            self.rebuild_display_lines();
        }
    }

    fn resolve_all_backtraces(&mut self) {
        for entry in self.entries.iter_mut() {
            if !entry.backtrace.is_empty() {
                let _ = self.resolver.resolve_frames(&mut entry.backtrace);
            }
        }
        self.rebuild_display_lines();
    }
}

/// Split arguments by comma, handling nested structures
pub fn split_arguments(args: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0; // Track nesting depth for (), {}, []
    let mut in_string = false;
    let mut escape_next = false;

    for ch in args.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' => {
                escape_next = true;
                current.push(ch);
            }
            '"' => {
                in_string = !in_string;
                current.push(ch);
            }
            '(' | '{' | '[' if !in_string => {
                depth += 1;
                current.push(ch);
            }
            ')' | '}' | ']' if !in_string => {
                depth -= 1;
                current.push(ch);
            }
            ',' if !in_string && depth == 0 => {
                // Split point
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    result.push(trimmed);
                }
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    // Don't forget the last argument
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        result.push(trimmed);
    }

    // If we couldn't parse any arguments, return the whole string
    if result.is_empty() && !args.trim().is_empty() {
        result.push(args.trim().to_string());
    }

    result
}
