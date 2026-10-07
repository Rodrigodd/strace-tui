use crate::parser::SyscallEntry;
use ratatui::style::Color;
use std::collections::{HashMap, HashSet};

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
    /// PID/TID that called the fork/clone that created this process
    pub parent_pid: Option<u32>,
    /// Index of the fork/clone entry that returned this process's PID
    pub fork_entry_idx: Option<usize>,
    /// Whether it was created by a clone with CLONE_THREAD
    pub is_thread: bool,
}

impl ProcessInfo {
    /// Order in which processes start. A root whose first syscall is a fork starts before the
    /// child created at that same entry.
    pub fn start_key(&self) -> (usize, bool, u32) {
        (
            self.first_entry_idx,
            self.fork_entry_idx.is_some(),
            self.pid,
        )
    }
}

#[derive(Debug)]
pub struct ProcessGraph {
    pub processes: HashMap<u32, ProcessInfo>,
    pub max_columns: usize,
    pub enabled: bool, // Hide graph if only one process
}

impl ProcessGraph {
    fn is_fork_syscall(syscall_name: &str) -> bool {
        matches!(syscall_name, "fork" | "vfork" | "clone" | "clone3")
    }

    fn is_wait_syscall(syscall_name: &str) -> bool {
        matches!(syscall_name, "wait4" | "waitid" | "waitpid")
    }

    pub fn build(entries: &[SyscallEntry]) -> Self {
        let mut processes: HashMap<u32, ProcessInfo> = HashMap::new();
        let mut pid_first_seen: HashMap<u32, usize> = HashMap::new();
        let mut pid_last_seen: HashMap<u32, usize> = HashMap::new();
        // (entry_idx, parent_pid, child_pid, is_thread)
        let mut fork_relationships: Vec<(usize, u32, u32, bool)> = Vec::new();

        // First pass: find all PIDs, their lifetimes, and fork relationships
        for (idx, entry) in entries.iter().enumerate() {
            let pid = entry.pid;

            // Track first and last appearance of each PID
            pid_first_seen.entry(pid).or_insert(idx);
            pid_last_seen.insert(pid, idx);

            // Detect fork syscalls
            if Self::is_fork_syscall(&entry.syscall_name)
                && let Some(ref ret) = entry.return_value
                // Try to parse return value as child PID
                && let Ok(child_pid) = ret.trim().parse::<u32>()
                && child_pid > 0
            {
                // For a resumed clone, the flags are in the unfinished entry's arguments
                let is_thread = entry.arguments.contains("CLONE_THREAD")
                    || entry
                        .unfinished_entry_idx
                        .and_then(|i| entries.get(i))
                        .is_some_and(|e| e.arguments.contains("CLONE_THREAD"));
                fork_relationships.push((idx, pid, child_pid, is_thread));
                pid_first_seen.entry(child_pid).or_insert(idx);
                pid_last_seen.insert(child_pid, idx);
            }

            // Detect wait syscalls, to update the last seen index of waited-for PIDs
            if Self::is_wait_syscall(&entry.syscall_name)
                && let Some(ref ret) = entry.return_value
                // Try to parse return value as waited PID
                && let Ok(waited_pid) = ret.trim().parse::<u32>()
                && waited_pid > 0
            {
                pid_last_seen.insert(waited_pid, idx);
            }
        }

        // Get all PIDs in order of first appearance, marking whether it's a start or end event
        let mut pids_ordered: Vec<(u32, usize, bool)> = pid_first_seen
            .into_iter()
            .map(|(pid, idx)| (pid, idx, false))
            .chain(pid_last_seen.iter().map(|(&pid, &idx)| (pid, idx, true)))
            .collect();
        // Break ties deterministically: starts before ends (so a column is not reused while both
        // processes are alive), and a root before the child it forks at that same entry.
        let fork_children: HashSet<u32> = fork_relationships
            .iter()
            .map(|(_, _, child, _)| *child)
            .collect();
        pids_ordered.sort_by_key(|&(pid, idx, end)| (idx, end, fork_children.contains(&pid), pid));

        // Second pass: Assign columns with reuse
        let mut free_columns: Vec<usize> = Vec::new();
        let mut max_columns = 0;

        for (index, (pid, idx, end)) in pids_ordered.into_iter().enumerate() {
            if end {
                if let Some(info) = processes.get(&pid) {
                    // Free the column for reuse
                    free_columns.push(info.column);
                }
                continue;
            }

            // Sort free_columns to always reuse the smallest available column
            free_columns.sort_unstable();

            // Assign column: reuse if available, otherwise allocate new
            let column = if !free_columns.is_empty() {
                free_columns.remove(0) // Take smallest free column
            } else {
                let col = max_columns;
                max_columns += 1;
                col
            };

            // Find parent if this was a fork child
            let fork = fork_relationships
                .iter()
                .find(|(_, _, child, _)| *child == pid);

            processes.insert(
                pid,
                ProcessInfo {
                    pid,
                    column,
                    color: GRAPH_COLORS[index % GRAPH_COLORS.len()],
                    first_entry_idx: idx,
                    last_entry_idx: pid_last_seen.get(&pid).cloned().unwrap_or(idx),
                    parent_pid: fork.map(|(_, parent, _, _)| *parent),
                    fork_entry_idx: fork.map(|(idx, _, _, _)| *idx),
                    is_thread: fork.is_some_and(|(_, _, _, thread)| *thread),
                },
            );
        }

        let enabled = max_columns > 1; // Hide graph if only one process

        ProcessGraph {
            processes,
            max_columns,
            enabled,
        }
    }

    pub fn get_color(&self, pid: u32) -> Color {
        self.processes
            .get(&pid)
            .map(|info| info.color)
            .unwrap_or(Color::White)
    }

    /// Which columns stay visible when `hidden` processes are removed.
    ///
    /// A column is dropped only when *every* process that ever occupied it is hidden; a column
    /// shared over time between a hidden and a visible process is kept. Returns a bitmask indexed
    /// by original column: `true` means the column is still drawn. A column with no process at all
    /// is kept (defensive; this should not happen).
    fn visible_columns(&self, hidden: &HashSet<u32>) -> Vec<bool> {
        let mut keep = vec![false; self.max_columns];
        let mut has_process = vec![false; self.max_columns];
        for info in self.processes.values() {
            if info.column >= self.max_columns {
                continue;
            }
            has_process[info.column] = true;
            if !hidden.contains(&info.pid) {
                keep[info.column] = true;
            }
        }
        for col in 0..self.max_columns {
            if !has_process[col] {
                keep[col] = true;
            }
        }
        keep
    }

    /// Drop the cells of fully-hidden columns, closing the gap so the remaining lanes stay
    /// contiguous. `graph` holds one cell per original column (what the `render_*` methods build).
    fn filter_hidden_columns(
        &self,
        graph: Vec<(char, Color)>,
        hidden: &HashSet<u32>,
    ) -> Vec<(char, Color)> {
        if hidden.is_empty() || graph.is_empty() {
            return graph;
        }
        let keep = self.visible_columns(hidden);
        graph
            .into_iter()
            .enumerate()
            .filter_map(|(col, cell)| keep.get(col).copied().unwrap_or(true).then_some(cell))
            .collect()
    }

    pub fn get_color_for_column(&self, column: usize, entry_idx: usize) -> Color {
        self.processes
            .values()
            .find(|info| {
                info.column == column
                    && entry_idx >= info.first_entry_idx
                    && entry_idx <= info.last_entry_idx
            })
            .map(|info| info.color)
            .unwrap_or(GRAPH_COLORS[column % GRAPH_COLORS.len()])
    }

    pub fn render_graph_for_entry(
        &self,
        entry_idx: usize,
        entries: &[SyscallEntry],
        hidden: &HashSet<u32>,
    ) -> Vec<(char, Color)> {
        if !self.enabled {
            return Vec::new();
        }

        let entry = match entries.get(entry_idx) {
            Some(e) => e,
            None => return Vec::new(),
        };

        let pid = entry.pid;
        let mut graph = Vec::new();

        // Check if this is a fork
        let is_fork = Self::is_fork_syscall(&entry.syscall_name) && !entry.is_resumed;
        let child_pid = if is_fork {
            if entry.is_unfinished {
                entry.resumed_entry_idx.and_then(|resumed_idx| {
                    entries
                        .get(resumed_idx)
                        .and_then(|resumed_entry| resumed_entry.return_value.as_ref())
                        .and_then(|ret| ret.trim().parse::<u32>().ok())
                        .filter(|&child| child > 0)
                })
            } else {
                entry
                    .return_value
                    .as_ref()
                    .and_then(|ret| ret.trim().parse::<u32>().ok())
                    .filter(|&child| child > 0)
            }
        } else {
            None
        };

        // Check if this is a wait that completes
        let is_wait = Self::is_wait_syscall(&entry.syscall_name);
        // For wait, use the return value (the reaped PID). A non-positive return (e.g. WNOHANG
        // with nothing to reap, or an error) means no process was reaped, so no merge is drawn.
        let waited_pid = if is_wait && !entry.is_unfinished {
            entry
                .return_value
                .as_ref()
                .and_then(|ret| ret.trim().parse::<u32>().ok())
                .filter(|&waited| waited > 0 && waited != pid)
        } else {
            None
        };

        let current_column = self.processes.get(&pid).map(|p| p.column).unwrap_or(0);

        // Build graph with colored characters column by column
        for col in 0..self.max_columns {
            let col_color = self.get_color_for_column(col, entry_idx);
            if let Some(child) = child_pid {
                let child_column = self.processes.get(&child).map(|p| p.column).unwrap_or(0);

                // Fork pattern: parent at current_column, child at child_column
                // Need to handle both directions (child left or right of parent)
                let min_col = current_column.min(child_column);
                let max_col = current_column.max(child_column);

                if col == current_column {
                    if entry.is_unfinished {
                        graph.push(('○', col_color));
                    } else {
                        graph.push(('●', col_color));
                    }
                } else if col > min_col && col < max_col {
                    graph.push(('─', col_color));
                } else if col == child_column {
                    let c = if child_column > current_column {
                        '┐'
                    } else {
                        '┌'
                    };
                    graph.push((c, col_color));
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
                    if entry.is_unfinished {
                        graph.push(('○', col_color));
                    } else {
                        graph.push(('●', col_color));
                    }
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
                    if entry.is_unfinished {
                        graph.push(('○', col_color));
                    } else {
                        graph.push(('●', col_color));
                    }
                } else if self.is_active_at(col, entry_idx) {
                    graph.push(('│', col_color));
                } else {
                    graph.push((' ', col_color));
                }
            }
        }

        self.filter_hidden_columns(graph, hidden)
    }

    /// Render the graph for the start of a process: `●` at its own column, and a branch from the
    /// parent's column (`├─●` or `●─┤`) if it has a known parent.
    pub fn render_process_start(&self, pid: u32, hidden: &HashSet<u32>) -> Vec<(char, Color)> {
        if !self.enabled {
            return Vec::new();
        }

        let Some(info) = self.processes.get(&pid) else {
            return Vec::new();
        };

        let entry_idx = info.first_entry_idx;
        // Only lanes of processes that started before this one are alive
        let is_alive = |col: usize| {
            self.processes.values().any(|other| {
                other.column == col
                    && other.start_key() < info.start_key()
                    && other.last_entry_idx >= entry_idx
            })
        };
        let parent_column = info
            .parent_pid
            .and_then(|parent| self.processes.get(&parent))
            .map(|parent| parent.column)
            .filter(|&col| col != info.column);

        let mut graph = Vec::new();
        for col in 0..self.max_columns {
            let col_color = self.get_color_for_column(col, entry_idx);
            let ch = if col == info.column {
                '●'
            } else if let Some(parent_col) = parent_column {
                let min_col = parent_col.min(info.column);
                let max_col = parent_col.max(info.column);
                if col == parent_col {
                    if parent_col < info.column {
                        '├'
                    } else {
                        '┤'
                    }
                } else if col > min_col && col < max_col {
                    '─'
                } else if is_alive(col) {
                    '│'
                } else {
                    ' '
                }
            } else if is_alive(col) {
                '│'
            } else {
                ' '
            };
            graph.push((ch, col_color));
        }

        self.filter_hidden_columns(graph, hidden)
    }

    fn is_active_at(&self, column: usize, entry_idx: usize) -> bool {
        self.processes.values().any(|info| {
            info.column == column
                && entry_idx >= info.first_entry_idx
                && entry_idx <= info.last_entry_idx
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::StraceParser;

    fn build(lines: &[&str]) -> ProcessGraph {
        let entries = StraceParser::new()
            .parse_lines(lines.iter().map(|l| l.to_string()), false)
            .unwrap();
        ProcessGraph::build(&entries)
    }

    fn chars(graph: &ProcessGraph, pid: u32) -> String {
        graph
            .render_process_start(pid, &HashSet::new())
            .into_iter()
            .map(|(c, _)| c)
            .collect()
    }

    fn chars_hidden(graph: &ProcessGraph, pid: u32, hidden: &[u32]) -> String {
        let hidden: HashSet<u32> = hidden.iter().copied().collect();
        graph
            .render_process_start(pid, &hidden)
            .into_iter()
            .map(|(c, _)| c)
            .collect()
    }

    #[test]
    fn test_parent_and_thread_flag() {
        let graph = build(&[
            "1 clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 2",
            "1 fork() = 3",
            "2 getpid() = 1",
            "3 getpid() = 3",
        ]);
        let thread = &graph.processes[&2];
        assert_eq!(thread.parent_pid, Some(1));
        assert_eq!(thread.fork_entry_idx, Some(0));
        assert!(thread.is_thread);
        let fork = &graph.processes[&3];
        assert_eq!(fork.parent_pid, Some(1));
        assert!(!fork.is_thread);
        assert_eq!(graph.processes[&1].parent_pid, None);
    }

    #[test]
    fn test_thread_flag_from_unfinished_clone() {
        let graph = build(&[
            "1 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88 <unfinished ...>",
            "1 <... clone3 resumed>) = 2",
            "2 getpid() = 1",
        ]);
        assert!(graph.processes[&2].is_thread);
    }

    #[test]
    fn test_render_process_start() {
        let graph = build(&[
            "1 fork() = 2",
            "2 fork() = 3",
            "3 getpid() = 3",
            "3 +++ exited with 0 +++",
            "2 +++ exited with 0 +++",
            "1 fork() = 4",
            "4 getpid() = 4",
        ]);
        assert_eq!(chars(&graph, 1), "●  ");
        assert_eq!(chars(&graph, 2), "├● ");
        assert_eq!(chars(&graph, 3), "│├●");
        // Process 4 reuses column 1, while column 2 is free
        assert_eq!(chars(&graph, 4), "├● ");
    }

    #[test]
    fn test_render_process_start_child_left_of_parent() {
        let graph = build(&[
            "1 fork() = 2",
            "1 fork() = 3",
            "2 +++ exited with 0 +++",
            "3 fork() = 4",
            "4 getpid() = 4",
            "1 wait4(-1, NULL, 0, NULL) = 3",
        ]);
        assert_eq!(graph.processes[&3].column, 2);
        assert_eq!(graph.processes[&4].column, 1);
        assert_eq!(chars(&graph, 4), "│●┤");
    }

    #[test]
    fn hidden_process_column_is_dropped() {
        // All three stay alive through process 3's start, so columns are distinct (0, 1, 2).
        let graph = build(&[
            "1 fork() = 2",
            "1 fork() = 3",
            "2 getpid() = 2",
            "3 getpid() = 3",
            "2 +++ exited with 0 +++",
            "3 +++ exited with 0 +++",
            "1 +++ exited with 0 +++",
        ]);
        assert_eq!(graph.processes[&1].column, 0);
        assert_eq!(graph.processes[&2].column, 1);
        assert_eq!(graph.processes[&3].column, 2);
        // Process 3 branches from parent 1 (column 0), with process 2 alive in column 1 between.
        assert_eq!(chars(&graph, 3), "├─●");
        // Hiding process 2 removes the middle lane; the parent→child connector stays contiguous.
        assert_eq!(chars_hidden(&graph, 3, &[2]), "├●");
        // Hiding process 1 (parent) drops the leftmost column.
        assert_eq!(chars_hidden(&graph, 3, &[1]), "─●");
    }

    #[test]
    fn column_shared_with_visible_process_is_kept() {
        let graph = build(&[
            "1 fork() = 2",
            "2 +++ exited with 0 +++",
            "1 fork() = 3",
            "3 getpid() = 3",
        ]);
        // Process 3 reuses process 2's freed column 1.
        assert_eq!(graph.processes[&2].column, graph.processes[&3].column);
        // Hiding process 2 must NOT drop column 1, since visible process 3 shares it.
        assert_eq!(chars_hidden(&graph, 3, &[2]), chars(&graph, 3));
    }

    #[test]
    fn hidden_middle_lane_in_syscall_graph_is_dropped() {
        let entries = StraceParser::new()
            .parse_lines(
                [
                    "1 fork() = 2",
                    "2 fork() = 3",
                    "1 getpid() = 1",
                    "3 getpid() = 3",
                    "2 getpid() = 2",
                ]
                .iter()
                .map(|l| l.to_string()),
                false,
            )
            .unwrap();
        let graph = ProcessGraph::build(&entries);
        // Entry 2 is "1 getpid()": all three lanes active -> "●││".
        let full: String = graph
            .render_graph_for_entry(2, &entries, &HashSet::new())
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        assert_eq!(full, "●││");
        // Hide process 2 (middle lane, column 1): its lane is dropped and the gap closes.
        let hidden: HashSet<u32> = [2].into_iter().collect();
        let filtered: String = graph
            .render_graph_for_entry(2, &entries, &hidden)
            .into_iter()
            .map(|(c, _)| c)
            .collect();
        assert_eq!(filtered, "●│");
    }
}

