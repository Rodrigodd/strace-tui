# strace-tui

A terminal user interface (TUI) for visualizing and exploring strace output.

## Overview

strace-tui is a Rust-based tool that parses strace output and provides an interactive TUI for exploring system call traces. It automatically detects and handles all common strace output formats:

**Format Support:**
- ✅ With PIDs and timestamps: `strace -f -t ...`
- ✅ With PIDs, no timestamps: `strace -f ...`
- ✅ With timestamps, no PIDs: `strace -t ...`
- ✅ No PIDs or timestamps: `strace ...`

**Supported features:**
- All syscall patterns (normal, unfinished, resumed)
- Single and multi-process traces (with or without `-f` flag)
- Timestamps (with or without `-t`/`-tt` flags)
- Kernel backtraces (`-k` flag)
- Signals and process exits
- On-demand backtrace resolution using addr2line

## Features

### TUI Mode (Default)
- **Interactive navigation**: Browse syscalls with arrow keys or vim-style (j/k)
- **Expandable details**: Press Enter to expand syscalls and view arguments, return values, errors
- **Backtrace exploration**: Toggle backtraces with Enter (resolves addresses on-demand)
- **Color coding**: Errors (red), signals (yellow), exits (cyan), resolved addresses (green)
- **Help overlay**: Press `?` for keybindings
- **Smooth scrolling**: Handles large traces efficiently

### JSON Mode
- **Structured output**: Use `--json` flag for programmatic access
- **Summary statistics**: Total syscalls, errors, PIDs, signals, etc.
- **Batch resolution**: Pre-resolve all backtraces with `-r`

## Installation

```bash
cargo build --release
# Binary will be at target/release/strace-tui
```

## Usage

### Parse an existing strace file (TUI)
```bash
strace-tui parse trace.txt
```

### Parse with JSON output
```bash
strace-tui parse trace.txt --json --pretty
strace-tui parse trace.txt --json --resolve --output result.json
```

### Run strace and visualize
```bash
strace-tui trace ls -la
strace-tui trace --keep-trace --trace-file my_trace.txt ./my_program
```

### TUI Keybindings
- `↑`/`↓` or `j`/`k`: Navigate through syscalls
- `Enter`/`Space`: Expand syscall details / Toggle backtrace
- `PageUp`/`PageDown`: Fast scroll
- `Home`/`g`: Jump to first
- `End`/`G`: Jump to last
- `e`: Expand all syscalls
- `c`: Collapse all
- `?` or `h`: Show help
- `q` or `Ctrl+C`: Quit

### Generating strace output

To create a trace file for use with strace-tui:

**Recommended options:**
```bash
# With timestamps and PIDs (most informative)
strace -o trace.txt -t -k -f -s 1024 <your_command>

# Single-process with timestamps
strace -o trace.txt -t -k -s 1024 <your_command>

# Without timestamps (smaller files)
strace -o trace.txt -k -f -s 1024 <your_command>
```

**Common flags:**
- `-t`: Include timestamps (optional but recommended)
- `-k`: Include kernel backtraces (optional)
- `-f`: Follow forks/clones - multi-process support (optional)
- `-s 1024`: Capture up to 1024 bytes of string arguments

**Note**: strace-tui automatically detects your trace format (with/without PIDs and timestamps) and handles all variations seamlessly.

## Examples

### Quick trace visualization
```bash
strace-tui trace cat /etc/hostname
```

### Complex multi-process trace
```bash
strace-tui trace bash -c "ls | wc -l"
```

### Export for analysis
```bash
strace-tui parse trace.txt --json --resolve --output analyzed.json
```

## Command-Line Options

### `parse` subcommand
Parse an existing strace output file.

```
strace-tui parse <FILE> [OPTIONS]
```

Options:
- `--json`: Output JSON instead of opening TUI
- `--resolve`, `-r`: Resolve backtraces using addr2line (JSON mode only)
- `--pretty`, `-p`: Pretty-print JSON output (JSON mode only)
- `--output <FILE>`, `-o <FILE>`: Write JSON to file (JSON mode only)

### `trace` subcommand
Run strace on a command and parse the output.

```
strace-tui trace <COMMAND> [ARGS...] [OPTIONS]
```

Options:
- `--json`: Output JSON instead of opening TUI
- `--resolve`, `-r`: Resolve backtraces using addr2line (JSON mode only)
- `--pretty`, `-p`: Pretty-print JSON output (JSON mode only)
- `--output <FILE>`, `-o <FILE>`: Write JSON to file (JSON mode only)
- `--keep-trace`, `-k`: Keep the strace output file
- `--trace-file <FILE>`: Path for strace output (default: temp file)

## JSON Output Format

When using `--json`, the output has the following structure:

```json
{
  "entries": [
    {
      "pid": 12345,
      "timestamp": "10:20:30",
      "syscall_name": "write",
      "arguments": "1, \"hello\\n\", 6",
      "return_value": "6",
      "errno": null,
      "duration": null,
      "backtrace": [
        {
          "binary": "/usr/lib/libc.so.6",
          "function": "__write",
          "offset": "0x14",
          "address": "0x10e53e",
          "resolved": {
            "file": "/build/glibc/io/write.c",
            "line": 27
          }
        }
      ],
      "is_unfinished": false,
      "is_resumed": false,
      "signal": null,
      "exit_info": null
    }
  ],
  "summary": {
    "total_syscalls": 252,
    "failed_syscalls": 3,
    "unique_pids": [12345, 12346],
    "signals": 0,
    "exits": 2
  },
  "errors": []
}
```

## Library Usage

strace-tui can also be used as a Rust library:

```rust
use strace_tui::parser::StraceParser;

let mut parser = StraceParser::new();
let entries = parser.parse_file("trace.txt")?;

for entry in entries {
    println!("{}: {} = {}",
        entry.timestamp,
        entry.syscall_name,
        entry.return_value.unwrap_or_default()
    );
}
```

## Architecture

### Parser
- Built using `nom` parser combinators
- Handles all strace output patterns:
  - Regular syscalls
  - Unfinished syscalls (`<unfinished ...>`)
  - Resumed syscalls (`<... resumed>`)
  - Signals (`--- SIGNAME ---`)
  - Process exits (`+++ exited with N +++`)
  - Kernel backtraces (multi-line ` > ` entries)

### Backtrace Resolution
- Shells out to system `addr2line` binary
- Caches results to avoid redundant lookups
- On-demand resolution in TUI mode for performance

### TUI
- Built with `ratatui` and `crossterm`
- Tree-style expandable list view
- Color-coded for quick visual parsing
- Lazy backtrace resolution (only when expanded)

## Requirements

- Rust 1.70+ (uses edition 2024)
- System binaries: `strace`, `addr2line` (for backtrace resolution)

## Known Limitations

- Duration parsing not yet implemented
- System libraries often lack debug symbols (addr2line returns `??`)
- Very large traces (10k+ syscalls) may be slow to navigate

## Testing

```bash
# Run all tests
cargo test

# Run with example program
cargo build --example syscall_test
strace -o trace.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test
strace-tui parse trace.txt
```

## License

See LICENSE file.

## Contributing

Contributions welcome! Please open an issue or PR.
