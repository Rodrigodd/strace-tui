use crate::parser::{Addr2LineResolver, SyscallEntry, SummaryStats};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashSet;
use super::process_graph::ProcessGraph;

#[derive(Debug, Clone)]
pub enum DisplayLine {
    SyscallHeader { entry_idx: usize },
    ArgumentsHeader { entry_idx: usize },
    ArgumentLine { entry_idx: usize, arg_idx: usize },
    ReturnValue { entry_idx: usize },
    Error { entry_idx: usize },
    Duration { entry_idx: usize },
    Signal { entry_idx: usize },
    Exit { entry_idx: usize },
    BacktraceHeader { entry_idx: usize },
    BacktraceFrame { entry_idx: usize, frame_idx: usize },
    BacktraceResolved { entry_idx: usize, frame_idx: usize },
}

impl DisplayLine {
    fn entry_idx(&self) -> usize {
        match self {
            DisplayLine::SyscallHeader { entry_idx } => *entry_idx,
            DisplayLine::ArgumentsHeader { entry_idx } => *entry_idx,
            DisplayLine::ArgumentLine { entry_idx, .. } => *entry_idx,
            DisplayLine::ReturnValue { entry_idx } => *entry_idx,
            DisplayLine::Error { entry_idx } => *entry_idx,
            DisplayLine::Duration { entry_idx } => *entry_idx,
            DisplayLine::Signal { entry_idx } => *entry_idx,
            DisplayLine::Exit { entry_idx } => *entry_idx,
            DisplayLine::BacktraceHeader { entry_idx } => *entry_idx,
            DisplayLine::BacktraceFrame { entry_idx, .. } => *entry_idx,
            DisplayLine::BacktraceResolved { entry_idx, .. } => *entry_idx,
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
            should_quit: false,
            show_help: false,
        };
        app.rebuild_display_lines();
        app
    }
    
    pub fn update_visible_height(&mut self, height: usize) {
        self.last_visible_height = height;
    }
    
    fn rebuild_display_lines(&mut self) {
        self.display_lines.clear();
        
        for (idx, entry) in self.entries.iter().enumerate() {
            // Always add the syscall header
            self.display_lines.push(DisplayLine::SyscallHeader { entry_idx: idx });
            
            // Add expanded details if item is expanded
            if self.expanded_items.contains(&idx) {
                if !entry.arguments.is_empty() {
                    self.display_lines.push(DisplayLine::ArgumentsHeader { entry_idx: idx });
                    
                    // Add arguments if expanded
                    if self.expanded_arguments.contains(&idx) {
                        let args = split_arguments(&entry.arguments);
                        for (arg_idx, _arg) in args.iter().enumerate() {
                            self.display_lines.push(DisplayLine::ArgumentLine { 
                                entry_idx: idx, 
                                arg_idx 
                            });
                        }
                    }
                }
                
                if entry.return_value.is_some() {
                    self.display_lines.push(DisplayLine::ReturnValue { entry_idx: idx });
                }
                
                if entry.errno.is_some() {
                    self.display_lines.push(DisplayLine::Error { entry_idx: idx });
                }
                
                if entry.duration.is_some() {
                    self.display_lines.push(DisplayLine::Duration { entry_idx: idx });
                }
                
                if entry.signal.is_some() {
                    self.display_lines.push(DisplayLine::Signal { entry_idx: idx });
                }
                
                if entry.exit_info.is_some() {
                    self.display_lines.push(DisplayLine::Exit { entry_idx: idx });
                }
                
                // Add backtrace header if there's a backtrace
                if !entry.backtrace.is_empty() {
                    self.display_lines.push(DisplayLine::BacktraceHeader { entry_idx: idx });
                    
                    // Add backtrace frames if expanded
                    if self.expanded_backtraces.contains(&idx) {
                        for (frame_idx, frame) in entry.backtrace.iter().enumerate() {
                            // Only show raw frame if NOT resolved
                            if frame.resolved.is_none() {
                                self.display_lines.push(DisplayLine::BacktraceFrame { 
                                    entry_idx: idx, 
                                    frame_idx 
                                });
                            } else {
                                // Show resolved version instead
                                self.display_lines.push(DisplayLine::BacktraceResolved { 
                                    entry_idx: idx, 
                                    frame_idx 
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
    }

    pub fn handle_event(&mut self, event: KeyEvent) {
        // Handle help screen toggle
        if self.show_help {
            if matches!(event.code, KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Esc) {
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
            KeyCode::Char('?') | KeyCode::Char('h') => {
                self.show_help = true;
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
        
        // Calculate cursor position relative to scroll_offset
        let cursor_offset = self.selected_line.saturating_sub(self.scroll_offset);
        
        if up {
            // Scroll up
            let scroll_amount = page_size.min(self.scroll_offset);
            self.scroll_offset = self.scroll_offset.saturating_sub(scroll_amount);
            self.selected_line = self.selected_line.saturating_sub(scroll_amount);
        } else {
            // Scroll down
            let max_scroll = self.display_lines.len().saturating_sub(self.last_visible_height);
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
        let last_line = self.display_lines.iter()
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
            let max_possible_scroll = self.display_lines.len().saturating_sub(self.last_visible_height);
            
            // Use the minimum of all constraints
            self.scroll_offset = needed_scroll.min(max_scroll).min(max_possible_scroll);
        }
    }
    
    fn toggle_current_line(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }
        
        match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx } => {
                // Toggle syscall expansion
                let idx = *entry_idx;
                if self.expanded_items.contains(&idx) {
                    log::debug!("Collapsing syscall {}", idx);
                    self.expanded_items.remove(&idx);
                    self.expanded_backtraces.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!("Expanding syscall {}, saving scroll_offset={}", idx, self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;
                    
                    self.expanded_items.insert(idx);
                    self.rebuild_display_lines();
                    
                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expansion adjustment, scroll_offset={}", self.scroll_offset);
                    return;
                }
                self.rebuild_display_lines();
            }
            DisplayLine::BacktraceHeader { entry_idx } => {
                // Toggle backtrace expansion
                let idx = *entry_idx;
                if self.expanded_backtraces.contains(&idx) {
                    log::debug!("Collapsing backtrace {}", idx);
                    self.expanded_backtraces.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!("Expanding backtrace {}, saving scroll_offset={}", idx, self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;
                    
                    self.expanded_backtraces.insert(idx);
                    // Resolve on-demand
                    if let Some(entry) = self.entries.get_mut(idx) {
                        if !entry.backtrace.is_empty() {
                            let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                        }
                    }
                    self.rebuild_display_lines();
                    
                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expansion adjustment, scroll_offset={}", self.scroll_offset);
                    return;
                }
                self.rebuild_display_lines();
            }
            DisplayLine::ArgumentsHeader { entry_idx } => {
                // Toggle arguments expansion
                let idx = *entry_idx;
                if self.expanded_arguments.contains(&idx) {
                    log::debug!("Collapsing arguments {}", idx);
                    self.expanded_arguments.remove(&idx);
                } else {
                    // Save scroll position before expanding
                    log::debug!("Expanding arguments {}, saving scroll_offset={}", idx, self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    let header_line = self.selected_line;
                    
                    self.expanded_arguments.insert(idx);
                    self.rebuild_display_lines();
                    
                    // Adjust scroll to show entire expanded item
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expansion adjustment, scroll_offset={}", self.scroll_offset);
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
        
        log::debug!("expand_current: selected_line={}, saved_position={:?}", 
                   self.selected_line, saved_position);
        
        match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx } => {
                // Expand syscall if not already expanded
                let idx = *entry_idx;
                if !self.expanded_items.contains(&idx) {
                    log::debug!("Expanding syscall {}", idx);
                    let header_line = self.selected_line;
                    
                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!("Saving scroll_offset={} for future collapse", self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    
                    self.expanded_items.insert(idx);
                    self.rebuild_display_lines();
                    
                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position {
                        if saved_line < self.display_lines.len() {
                            log::debug!("Restoring cursor position to {}", saved_line);
                            self.selected_line = saved_line;
                        }
                    }
                    
                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expand_current (syscall), scroll_offset={}", self.scroll_offset);
                }
            }
            DisplayLine::ArgumentsHeader { entry_idx } => {
                // Expand arguments if not already expanded
                let idx = *entry_idx;
                if !self.expanded_arguments.contains(&idx) {
                    log::debug!("Expanding arguments {}", idx);
                    let header_line = self.selected_line;
                    
                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!("Saving scroll_offset={} for future collapse", self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    
                    self.expanded_arguments.insert(idx);
                    self.rebuild_display_lines();
                    
                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position {
                        if saved_line < self.display_lines.len() {
                            log::debug!("Restoring cursor position to {}", saved_line);
                            self.selected_line = saved_line;
                        }
                    }
                    
                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expand_current (arguments), scroll_offset={}", self.scroll_offset);
                }
            }
            DisplayLine::BacktraceHeader { entry_idx } => {
                // Expand backtrace if not already expanded
                let idx = *entry_idx;
                if !self.expanded_backtraces.contains(&idx) {
                    log::debug!("Expanding backtrace {}", idx);
                    let header_line = self.selected_line;
                    
                    // Save current scroll for future collapse (always save before expanding)
                    log::debug!("Saving scroll_offset={} for future collapse", self.scroll_offset);
                    self.last_collapsed_scroll = Some(self.scroll_offset);
                    
                    self.expanded_backtraces.insert(idx);
                    // Resolve on-demand
                    if let Some(entry) = self.entries.get_mut(idx) {
                        if !entry.backtrace.is_empty() {
                            let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                        }
                    }
                    self.rebuild_display_lines();
                    
                    // Restore cursor position if we just collapsed this
                    if let Some(saved_line) = saved_position {
                        if saved_line < self.display_lines.len() {
                            log::debug!("Restoring cursor position to {}", saved_line);
                            self.selected_line = saved_line;
                        }
                    }
                    
                    // Always adjust scroll to show full list when expanding
                    log::debug!("Adjusting scroll after expansion");
                    self.adjust_scroll_after_expansion(header_line);
                    log::debug!("After expand_current (backtrace), scroll_offset={}", self.scroll_offset);
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
        
        log::debug!("collapse_deepest: selected_line={}, scroll_offset={}, last_collapsed_scroll={:?}", 
                   self.selected_line, self.scroll_offset, self.last_collapsed_scroll);
        
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
                    .position(|line| matches!(line, DisplayLine::ArgumentsHeader { entry_idx: i } if *i == idx))
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
                    .position(|line| matches!(line, DisplayLine::BacktraceHeader { entry_idx: i } if *i == idx))
                    .unwrap_or(self.selected_line);
            }
            DisplayLine::ArgumentsHeader { entry_idx } => {
                // On arguments header -> collapse arguments
                let idx = *entry_idx;
                self.expanded_arguments.remove(&idx);
                self.rebuild_display_lines();
                // Already on header, no need to move
            }
            DisplayLine::BacktraceHeader { entry_idx } => {
                // On backtrace header -> collapse backtrace
                let idx = *entry_idx;
                self.expanded_backtraces.remove(&idx);
                self.rebuild_display_lines();
                // Already on header, no need to move
            }
            DisplayLine::SyscallHeader { entry_idx } 
            | DisplayLine::ReturnValue { entry_idx }
            | DisplayLine::Error { entry_idx }
            | DisplayLine::Duration { entry_idx }
            | DisplayLine::Signal { entry_idx }
            | DisplayLine::Exit { entry_idx } => {
                // On syscall header or other top-level items -> collapse entire syscall
                let idx = *entry_idx;
                self.expanded_items.remove(&idx);
                self.expanded_arguments.remove(&idx);
                self.expanded_backtraces.remove(&idx);
                self.rebuild_display_lines();
                
                // Move cursor to SyscallHeader
                self.selected_line = self.display_lines.iter()
                    .position(|line| matches!(line, DisplayLine::SyscallHeader { entry_idx: i } if *i == idx))
                    .unwrap_or(self.selected_line);
            }
        }
        
        // Restore the scroll position from before expansion
        if let Some(scroll) = scroll_to_restore {
            log::debug!("Restoring scroll_offset from {} to {}", self.scroll_offset, scroll);
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
            DisplayLine::SyscallHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::ArgumentsHeader { entry_idx } => {
                // For arguments header, collapse just the arguments
                let idx = *entry_idx;
                self.expanded_arguments.remove(&idx);
                self.rebuild_display_lines();
                return;
            }
            DisplayLine::ArgumentLine { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ReturnValue { entry_idx } => Some(*entry_idx),
            DisplayLine::Error { entry_idx } => Some(*entry_idx),
            DisplayLine::Duration { entry_idx } => Some(*entry_idx),
            DisplayLine::Signal { entry_idx } => Some(*entry_idx),
            DisplayLine::Exit { entry_idx } => Some(*entry_idx),
            DisplayLine::BacktraceHeader { entry_idx } => {
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
            self.selected_line = self.display_lines.iter()
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
            self.selected_line = self.display_lines.iter()
                .position(|line| line.entry_idx() == entry_idx)
                .unwrap_or(0);
            
            // Restore cursor screen position
            self.scroll_offset = self.selected_line.saturating_sub(cursor_screen_pos);
        }
    }

    fn resolve_current_backtrace(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }
        
        // Find the entry_idx from the current line
        let entry_idx = match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::ArgumentsHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::ArgumentLine { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::ReturnValue { entry_idx } => Some(*entry_idx),
            DisplayLine::Error { entry_idx } => Some(*entry_idx),
            DisplayLine::Duration { entry_idx } => Some(*entry_idx),
            DisplayLine::Signal { entry_idx } => Some(*entry_idx),
            DisplayLine::Exit { entry_idx } => Some(*entry_idx),
            DisplayLine::BacktraceHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::BacktraceFrame { entry_idx, .. } => Some(*entry_idx),
            DisplayLine::BacktraceResolved { entry_idx, .. } => Some(*entry_idx),
        };
        
        if let Some(idx) = entry_idx {
            if let Some(entry) = self.entries.get_mut(idx) {
                if !entry.backtrace.is_empty() {
                    let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                    self.rebuild_display_lines();
                }
            }
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
