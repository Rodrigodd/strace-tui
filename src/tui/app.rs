use crate::parser::{Addr2LineResolver, SyscallEntry, SummaryStats};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashSet;

pub struct App {
    // Data
    pub entries: Vec<SyscallEntry>,
    pub resolver: Addr2LineResolver,
    pub summary: SummaryStats,
    pub file_path: Option<String>,
    
    // UI State
    pub selected_index: usize,
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
        Self {
            entries,
            resolver: Addr2LineResolver::new(),
            summary,
            file_path,
            selected_index: 0,
            scroll_offset: 0,
            expanded_items: HashSet::new(),
            expanded_backtraces: HashSet::new(),
            should_quit: false,
            show_help: false,
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
                self.selected_index = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                if !self.entries.is_empty() {
                    self.selected_index = self.entries.len() - 1;
                }
            }

            // Expand/Collapse
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.toggle_expansion();
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
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    fn move_down(&mut self) {
        if self.selected_index + 1 < self.entries.len() {
            self.selected_index += 1;
        }
    }

    fn toggle_expansion(&mut self) {
        if self.expanded_items.contains(&self.selected_index) {
            // If already expanded, try to toggle backtrace instead of collapsing
            if let Some(entry) = self.entries.get(self.selected_index) {
                if !entry.backtrace.is_empty() {
                    // Toggle backtrace
                    if self.expanded_backtraces.contains(&self.selected_index) {
                        self.expanded_backtraces.remove(&self.selected_index);
                    } else {
                        self.expanded_backtraces.insert(self.selected_index);
                        // Resolve on-demand
                        if let Some(entry_mut) = self.entries.get_mut(self.selected_index) {
                            let _ = self.resolver.resolve_frames(&mut entry_mut.backtrace);
                        }
                    }
                } else {
                    // No backtrace, just collapse
                    self.expanded_items.remove(&self.selected_index);
                }
            }
        } else {
            // Expand the item
            self.expanded_items.insert(self.selected_index);
        }
    }

    fn collapse_current(&mut self) {
        self.expanded_items.remove(&self.selected_index);
        self.expanded_backtraces.remove(&self.selected_index);
    }

    fn expand_all(&mut self) {
        for i in 0..self.entries.len() {
            self.expanded_items.insert(i);
        }
    }

    fn collapse_all(&mut self) {
        self.expanded_items.clear();
        self.expanded_backtraces.clear();
    }

    fn resolve_current_backtrace(&mut self) {
        if let Some(entry) = self.entries.get_mut(self.selected_index) {
            if !entry.backtrace.is_empty() {
                let _ = self.resolver.resolve_frames(&mut entry.backtrace);
            }
        }
    }

    fn resolve_all_backtraces(&mut self) {
        for entry in self.entries.iter_mut() {
            if !entry.backtrace.is_empty() {
                let _ = self.resolver.resolve_frames(&mut entry.backtrace);
            }
        }
    }
}
