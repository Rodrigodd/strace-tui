use serde::{Deserialize, Serialize};

/// A single syscall entry from strace output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEntry {
    /// Process ID
    pub pid: u32,

    /// Timestamp (HH:MM:SS format from strace -t)
    pub timestamp: String,

    /// Syscall name
    pub syscall_name: String,

    /// Raw argument string
    pub arguments: String,

    /// Return value (if available)
    pub return_value: Option<String>,

    /// Error number and message (if syscall failed)
    pub errno: Option<Errno>,

    /// Duration in seconds (from <0.000123> format)
    pub duration: Option<f64>,

    /// Stack backtrace frames (from -k flag)
    pub backtrace: Vec<BacktraceFrame>,

    /// Whether this is an unfinished syscall
    pub is_unfinished: bool,

    /// Whether this is a resumed syscall
    pub is_resumed: bool,

    /// Signal information (if this line is a signal)
    pub signal: Option<SignalInfo>,

    /// Exit information (if this is an exit line)
    pub exit_info: Option<ExitInfo>,
}

/// Error information from a failed syscall
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Errno {
    /// Error code (e.g., "ENOENT")
    pub code: String,

    /// Error message (e.g., "No such file or directory")
    pub message: String,
}

/// A single stack frame from the backtrace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktraceFrame {
    /// Binary/library path
    pub binary: String,

    /// Function name (if available)
    pub function: Option<String>,

    /// Offset within function (if available)
    pub offset: Option<String>,

    /// Memory address
    pub address: String,

    /// Resolved source locations (can be multiple due to inlining)
    pub resolved: Option<Vec<ResolvedFrame>>,
}

/// A resolved frame (can be inlined)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedFrame {
    /// Function name (demangled)
    pub function: String,

    /// Source file path
    pub file: String,

    /// Line number
    pub line: u32,

    /// Column number (if available)
    pub column: Option<u32>,

    /// True if this frame is inlined (all but the last frame)
    pub is_inlined: bool,
}

/// Signal delivery information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalInfo {
    /// Signal name (e.g., "SIGCHLD")
    pub signal_name: String,

    /// Raw signal details
    pub details: String,
}

/// Process exit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    /// Exit code
    pub code: i32,

    /// Whether it was killed by signal
    pub killed: bool,
}

impl SyscallEntry {
    /// Create a new syscall entry with basic information
    pub fn new(pid: u32, timestamp: String, syscall_name: String) -> Self {
        Self {
            pid,
            timestamp,
            syscall_name,
            arguments: String::new(),
            return_value: None,
            errno: None,
            duration: None,
            backtrace: Vec::new(),
            is_unfinished: false,
            is_resumed: false,
            signal: None,
            exit_info: None,
        }
    }
}

/// Output format containing all parsed data
#[derive(Debug, Serialize, Deserialize)]
pub struct StraceOutput {
    /// All syscall entries
    pub entries: Vec<SyscallEntry>,

    /// Summary statistics
    pub summary: SummaryStats,

    /// Parse errors encountered
    pub errors: Vec<ParseErrorInfo>,
}

/// Summary statistics about the trace
#[derive(Debug, Serialize, Deserialize)]
pub struct SummaryStats {
    /// Total number of syscalls
    pub total_syscalls: usize,

    /// Number of failed syscalls
    pub failed_syscalls: usize,

    /// Number of signals
    pub signals: usize,

    /// Unique PIDs seen
    pub unique_pids: Vec<u32>,

    /// Total duration (if available)
    pub total_duration: Option<f64>,
}

/// Information about a parse error
#[derive(Debug, Serialize, Deserialize)]
pub struct ParseErrorInfo {
    /// Line number where error occurred
    pub line_number: usize,

    /// Error message
    pub message: String,
}
