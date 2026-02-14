use crate::parser::SyscallEntry;
use ratatui::style::Color;
use std::collections::HashMap;

const GRAPH_COLORS: &[Color] = &[
    Color::Blue,
    Color::Green,
    Color::Yellow,
    Color::Magenta,
    Color::Cyan,
    Color::LightBlue,
    Color::LightGreen,
    Color::LightMagenta,
];

#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub column: usize,
    pub color: Color,
    pub first_entry_idx: usize,
    pub last_entry_idx: usize,
    pub parent_pid: Option<u32>,
}

#[derive(Debug)]
pub struct ProcessGraph {
    pub processes: HashMap<u32, ProcessInfo>,
    pub max_columns: usize,
    pub enabled: bool, // Hide graph if only one process
}

impl ProcessGraph {
    pub fn build(entries: &[SyscallEntry]) -> Self {
        let mut processes: HashMap<u32, ProcessInfo> = HashMap::new();
        let mut pid_first_seen: HashMap<u32, usize> = HashMap::new();
        let mut next_column = 0;
        let mut fork_relationships: Vec<(usize, u32, u32)> = Vec::new(); // (entry_idx, parent_pid, child_pid)
        
        // First pass: find all PIDs and fork relationships
        for (idx, entry) in entries.iter().enumerate() {
            let pid = entry.pid;
            
            // Track first and last appearance of each PID
            pid_first_seen.entry(pid).or_insert(idx);
            
            // Detect fork syscalls
            if matches!(entry.syscall_name.as_str(), "fork" | "vfork" | "clone" | "clone3") {
                if let Some(ref ret) = entry.return_value {
                    // Try to parse return value as child PID
                    if let Ok(child_pid) = ret.trim().parse::<u32>() {
                        if child_pid > 0 {
                            fork_relationships.push((idx, pid, child_pid));
                        }
                    }
                }
            }
        }
        
        // Get unique PIDs in order of first appearance
        let mut pids_ordered: Vec<(u32, usize)> = pid_first_seen.into_iter().collect();
        pids_ordered.sort_by_key(|(_, first_idx)| *first_idx);
        
        // Assign columns to PIDs
        for (pid, first_idx) in pids_ordered {
            let column = next_column;
            next_column += 1;
            
            // Find parent if this was a fork child
            let parent_pid = fork_relationships.iter()
                .find(|(_, _, child)| *child == pid)
                .map(|(_, parent, _)| *parent);
            
            processes.insert(pid, ProcessInfo {
                pid,
                column,
                color: GRAPH_COLORS[column % GRAPH_COLORS.len()],
                first_entry_idx: first_idx,
                last_entry_idx: first_idx, // Will update in second pass
                parent_pid,
            });
        }
        
        // Second pass: update last_entry_idx
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(info) = processes.get_mut(&entry.pid) {
                info.last_entry_idx = idx;
            }
        }
        
        let max_columns = next_column;
        let enabled = max_columns > 1; // Hide graph if only one process
        
        ProcessGraph {
            processes,
            max_columns,
            enabled,
        }
    }
    
    pub fn get_color(&self, pid: u32) -> Color {
        self.processes.get(&pid)
            .map(|info| info.color)
            .unwrap_or(Color::White)
    }
    
    pub fn get_color_for_column(&self, column: usize) -> Color {
        GRAPH_COLORS[column % GRAPH_COLORS.len()]
    }
    
    pub fn render_graph_for_entry(&self, entry_idx: usize, entry: &SyscallEntry) -> Vec<(char, Color)> {
        if !self.enabled {
            return Vec::new();
        }
        
        let pid = entry.pid;
        let mut graph = Vec::new();
        
        // Check if this is a fork
        let is_fork = matches!(entry.syscall_name.as_str(), "fork" | "vfork" | "clone" | "clone3");
        let child_pid = if is_fork {
            entry.return_value.as_ref()
                .and_then(|ret| ret.trim().parse::<u32>().ok())
                .filter(|&child| child > 0)
        } else {
            None
        };
        
        // Check if this is a wait that completes
        let is_wait = matches!(entry.syscall_name.as_str(), "wait4" | "waitid" | "waitpid");
        // For wait, try return value first, then fall back to first argument (the PID waited for)
        let waited_pid = if is_wait {
            entry.return_value.as_ref()
                .and_then(|ret| ret.trim().parse::<u32>().ok())
                .filter(|&waited| waited > 0 && waited != pid)
                .or_else(|| {
                    // If return value not available, try parsing first argument
                    entry.arguments.split(',').next()
                        .and_then(|arg| arg.trim().parse::<u32>().ok())
                        .filter(|&waited| waited > 0 && waited != pid)
                })
        } else {
            None
        };
        
        let current_column = self.processes.get(&pid).map(|p| p.column).unwrap_or(0);
        
        // Build graph with colored characters column by column
        for col in 0..self.max_columns {
            let col_color = self.get_color_for_column(col);
            if let Some(child) = child_pid {
                let child_column = self.processes.get(&child).map(|p| p.column).unwrap_or(0);
                
                // Fork pattern: parent at current_column, child at child_column
                // Need to handle both directions (child left or right of parent)
                let min_col = current_column.min(child_column);
                let max_col = current_column.max(child_column);
                
                if col == current_column {
                    graph.push(('*', col_color));
                } else if col > min_col && col < max_col {
                    graph.push(('─', col_color));
                } else if col == child_column {
                    graph.push(('┐', col_color));
                } else if self.is_active_at(col, entry_idx) {
                    graph.push(('│', col_color));
                } else {
                    graph.push((' ', col_color));
                }
            } else if let Some(waited) = waited_pid {
                let waited_column = self.processes.get(&waited).map(|p| p.column).unwrap_or(0);
                
                // Wait pattern: parent at current_column, merges back to waited_column
                // Need to handle both directions (child left or right of parent)
                let min_col = current_column.min(waited_column);
                let max_col = current_column.max(waited_column);
                
                if col == current_column {
                    graph.push(('*', col_color));
                } else if col > min_col && col < max_col {
                    graph.push(('─', col_color));
                } else if col == waited_column {
                    graph.push(('┘', col_color));
                } else if self.is_active_at(col, entry_idx) {
                    graph.push(('│', col_color));
                } else {
                    graph.push((' ', col_color));
                }
            } else {
                // Normal line: show active processes
                if col == current_column {
                    graph.push(('*', col_color));
                } else if self.is_active_at(col, entry_idx) {
                    graph.push(('│', col_color));
                } else {
                    graph.push((' ', col_color));
                }
            }
        }
        
        graph
    }
    
    fn is_active_at(&self, column: usize, entry_idx: usize) -> bool {
        self.processes.values().any(|info| {
            info.column == column 
                && entry_idx >= info.first_entry_idx 
                && entry_idx <= info.last_entry_idx
        })
    }
}
