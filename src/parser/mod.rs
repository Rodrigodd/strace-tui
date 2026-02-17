mod backtrace_parser;
mod line_parser;
mod resolver;
mod types;

pub use backtrace_parser::parse_backtrace_line;
pub use line_parser::parse_strace_line;
pub use resolver::Addr2LineResolver;
pub use types::*;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// Parse errors that can occur during strace parsing
#[derive(Debug, Clone, thiserror::Error)]
pub enum ParseError {
    #[error("Invalid line format: {0}")]
    InvalidFormat(String),

    #[error("Invalid syscall format: {0}")]
    InvalidSyscall(String),

    #[error("Failed to parse backtrace: {0}")]
    InvalidBacktrace(String),

    #[error("IO error: {0}")]
    Io(String),
}

/// Result type for parser operations
pub type ParseResult<T> = Result<T, ParseError>;

/// Parser state for handling multi-line entries and unfinished syscalls
#[derive(Debug)]
pub struct StraceParser {
    /// Pending unfinished syscalls, keyed by PID
    unfinished: HashMap<u32, usize>,
    /// Accumulated errors during parsing
    pub errors: Vec<(usize, ParseError)>,
    /// Current line number
    line_number: usize,
}

impl StraceParser {
    pub fn new() -> Self {
        Self {
            unfinished: HashMap::new(),
            errors: Vec::new(),
            line_number: 0,
        }
    }

    /// Parse an entire strace output file
    pub fn parse_file(&mut self, path: &str) -> ParseResult<Vec<SyscallEntry>> {
        let file = File::open(path)
            .map_err(|e| ParseError::Io(format!("Failed to open {}: {}", path, e)))?;

        let reader = BufReader::new(file);
        self.parse_lines(reader.lines().map(|l| l.unwrap_or_default()))
    }

    /// Parse strace output from an iterator of lines
    pub fn parse_lines<I>(&mut self, lines: I) -> ParseResult<Vec<SyscallEntry>>
    where
        I: Iterator<Item = String>,
    {
        let mut entries = Vec::new();
        let mut current_entry: Option<SyscallEntry> = None;

        for line in lines {
            self.line_number += 1;

            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }

            // Check if this is a backtrace line (starts with " > ")
            if line.trim_start().starts_with(">") {
                if let Some(ref mut entry) = current_entry {
                    match parse_backtrace_line(&line) {
                        Ok(frame) => entry.backtrace.push(frame),
                        Err(e) => self.errors.push((self.line_number, e)),
                    }
                }
                continue;
            }

            // If we have a pending entry, finalize it
            if let Some(entry) = current_entry.take() {
                entries.push(entry);
            }

            // Parse the syscall line
            match parse_strace_line(&line) {
                Ok(entry) => {
                    // Handle special cases
                    if entry.is_unfinished {
                        // Store unfinished syscall
                        self.unfinished.insert(entry.pid, entries.len());
                        current_entry = Some(entry);
                    } else if entry.is_resumed {
                        // Complete previously unfinished syscall
                        if let Some(unfinished) = self.unfinished.remove(&entry.pid) {
                            let unfinished = entries.get_mut(unfinished).unwrap();
                            unfinished.return_value = entry.return_value;
                            unfinished.errno = entry.errno;
                            unfinished.duration = entry.duration;
                            unfinished.is_resumed = false;
                            unfinished.is_unfinished = false;
                        } else {
                            // Resumed without unfinished - just store as-is with error
                            self.errors.push((
                                self.line_number,
                                ParseError::InvalidFormat("resumed without unfinished".to_string()),
                            ));
                            current_entry = Some(entry);
                        }
                    } else {
                        current_entry = Some(entry);
                    }
                }
                Err(e) => {
                    self.errors.push((self.line_number, e));
                }
            }
        }

        // Don't forget the last entry
        if let Some(entry) = current_entry {
            entries.push(entry);
        }

        Ok(entries)
    }
}

impl Default for StraceParser {
    fn default() -> Self {
        Self::new()
    }
}
