use crate::parser::{Addr2LineResolver, SyscallEntry, SummaryStats};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub enum DisplayLine {
    SyscallHeader { entry_idx: usize },
    Arguments { entry_idx: usize },
    ReturnValue { entry_idx: usize },
    Error { entry_idx: usize },
    Duration { entry_idx: usize },
    Signal { entry_idx: usize },
    Exit { entry_idx: usize },
    BacktraceHeader { entry_idx: usize },
    BacktraceFrame { entry_idx: usize, frame_idx: usize },
    BacktraceResolved { entry_idx: usize, frame_idx: usize },
}

pub struct App {
    // Data
    pub entries: Vec<SyscallEntry>,
    pub resolver: Addr2LineResolver,
    pub summary: SummaryStats,
    pub file_path: Option<String>,
    
    // UI State
    pub display_lines: Vec<DisplayLine>,
    pub selected_line: usize,
    pub scroll_offset: usize,
    pub expanded_items: HashSet<usize>,
    pub expanded_backtraces: HashSet<usize>,
    
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
        let mut app = Self {
            entries,
            resolver: Addr2LineResolver::new(),
            summary,
            file_path,
            display_lines: Vec::new(),
            selected_line: 0,
            scroll_offset: 0,
            expanded_items: HashSet::new(),
            expanded_backtraces: HashSet::new(),
            should_quit: false,
            show_help: false,
        };
        app.rebuild_display_lines();
        app
    }
    
    fn rebuild_display_lines(&mut self) {
        self.display_lines.clear();
        
        for (idx, entry) in self.entries.iter().enumerate() {
            // Always add the syscall header
            self.display_lines.push(DisplayLine::SyscallHeader { entry_idx: idx });
            
            // Add expanded details if item is expanded
            if self.expanded_items.contains(&idx) {
                if !entry.arguments.is_empty() {
                    self.display_lines.push(DisplayLine::Arguments { entry_idx: idx });
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
                            self.display_lines.push(DisplayLine::BacktraceFrame { 
                                entry_idx: idx, 
                                frame_idx 
                            });
                            
                            if frame.resolved.is_some() {
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
                for _ in 0..10 {
                    self.move_up();
                }
            }
            KeyCode::PageDown => {
                for _ in 0..10 {
                    self.move_down();
                }
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
        if self.selected_line > 0 {
            self.selected_line -= 1;
        }
    }

    fn move_down(&mut self) {
        if self.selected_line + 1 < self.display_lines.len() {
            self.selected_line += 1;
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
                    self.expanded_items.remove(&idx);
                    self.expanded_backtraces.remove(&idx);
                } else {
                    self.expanded_items.insert(idx);
                }
                self.rebuild_display_lines();
            }
            DisplayLine::BacktraceHeader { entry_idx } => {
                // Toggle backtrace expansion
                let idx = *entry_idx;
                if self.expanded_backtraces.contains(&idx) {
                    self.expanded_backtraces.remove(&idx);
                } else {
                    self.expanded_backtraces.insert(idx);
                    // Resolve on-demand
                    if let Some(entry) = self.entries.get_mut(idx) {
                        if !entry.backtrace.is_empty() {
                            let _ = self.resolver.resolve_frames(&mut entry.backtrace);
                        }
                    }
                }
                self.rebuild_display_lines();
            }
            _ => {
                // For other line types, do nothing on Enter
            }
        }
    }

    fn collapse_current(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }
        
        // Find the entry_idx of the current line and collapse it
        let entry_idx = match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::Arguments { entry_idx } => Some(*entry_idx),
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
            self.expanded_backtraces.remove(&idx);
            self.rebuild_display_lines();
        }
    }

    fn expand_all(&mut self) {
        for i in 0..self.entries.len() {
            self.expanded_items.insert(i);
        }
        self.rebuild_display_lines();
    }

    fn collapse_all(&mut self) {
        self.expanded_items.clear();
        self.expanded_backtraces.clear();
        self.rebuild_display_lines();
    }

    fn resolve_current_backtrace(&mut self) {
        if self.selected_line >= self.display_lines.len() {
            return;
        }
        
        // Find the entry_idx from the current line
        let entry_idx = match &self.display_lines[self.selected_line] {
            DisplayLine::SyscallHeader { entry_idx } => Some(*entry_idx),
            DisplayLine::Arguments { entry_idx } => Some(*entry_idx),
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
