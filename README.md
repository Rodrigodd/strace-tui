# strace-tui

A Rust-based parser and analyzer for `strace` output, with plans for an interactive terminal UI.

## Features

- ✅ **Comprehensive strace parser** - Handles all major strace output patterns
- ✅ **Backtrace support** - Parses kernel stack traces from `-k` flag
- ✅ **Address resolution** - Resolves addresses to source locations using `addr2line`
- ✅ **Multi-process traces** - Handles `-f` flag with PID tracking
- ✅ **Signal and exit events** - Parses signal deliveries and process termination
- ✅ **Unfinished/resumed syscalls** - Correctly handles async syscall patterns
- ✅ **JSON output** - Structured data output for further analysis
- ✅ **Error collection** - Reports all parse errors with line numbers
- 🚧 **TUI visualization** - Coming soon

## Installation

```bash
cargo install --path .
```

## Usage

### Basic Usage

The tool has two main subcommands: `parse` for existing strace files and `trace` for running strace directly.

#### Parse existing strace output

First, generate strace output with the required flags:

```bash
strace -o trace.txt -t -k -f -s 1024 <command>
```

Then parse it:

```bash
# Basic parsing to stdout
strace-tui parse trace.txt

# Pretty-printed JSON
strace-tui parse trace.txt --pretty

# Resolve addresses to source locations
strace-tui parse trace.txt --resolve --output parsed.json
```

#### Trace and parse in one command

Run strace and parse the output automatically:

```bash
# Trace any command
strace-tui trace <command> [args...]

# Examples
strace-tui trace ls -la
strace-tui trace --pretty echo "Hello"
strace-tui trace --resolve ./my_program arg1 arg2

# Keep the intermediate strace file
strace-tui trace --keep-trace --trace-file my_trace.txt ./my_program

# Output to file
strace-tui trace --output result.json python script.py
```

### Flag Explanations

**strace flags** (used automatically by `trace` subcommand):
- `-o trace.txt` - Write output to file
- `-t` - Include timestamps
- `-k` - Include kernel backtraces
- `-f` - Follow forks (trace child processes)
- `-s 1024` - Capture up to 1024 bytes of string arguments

**strace-tui options**:
- `--resolve` / `-r` - Resolve addresses to source locations using addr2line
- `--pretty` / `-p` - Pretty-print JSON output
- `--output <file>` / `-o <file>` - Write to file instead of stdout
- `--keep-trace` - Keep intermediate strace file (trace subcommand only)
- `--trace-file <file>` - Specify strace output file path (trace subcommand only)

## Output Format

The parser outputs JSON with three main sections:

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
      "duration": 0.000123,
      "backtrace": [
        {
          "binary": "/usr/lib/libc.so.6",
          "function": "__write",
          "offset": "0x14",
          "address": "0x10e53e",
          "resolved": {
            "file": "/build/glibc/io/write.c",
            "line": 27,
            "column": null
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
    "failed_syscalls": 9,
    "signals": 2,
    "unique_pids": [12345, 12346],
    "total_duration": 1.234
  },
  "errors": []
}
```

## Library Usage

You can use strace-tui as a library in your own Rust projects:

```rust
use strace_tui::{StraceParser, Addr2LineResolver};

fn main() {
    // Parse strace output
    let mut parser = StraceParser::new();
    let mut entries = parser.parse_file("trace.txt").unwrap();
    
    println!("Parsed {} syscalls", entries.len());
    
    // Optionally resolve backtraces
    let mut resolver = Addr2LineResolver::new();
    for entry in entries.iter_mut() {
        resolver.resolve_frames(&mut entry.backtrace).ok();
    }
    
    // Check for errors
    if !parser.errors.is_empty() {
        eprintln!("Parse errors: {}", parser.errors.len());
        for (line, err) in &parser.errors {
            eprintln!("  Line {}: {}", line, err);
        }
    }
}
```

## CLI Examples

```bash
# Parse an existing trace file
strace-tui parse my_trace.txt --pretty

# Trace a simple command
strace-tui trace echo "Hello, World!"

# Trace with address resolution
strace-tui trace --resolve ./my_program

# Trace and save both strace output and JSON
strace-tui trace --keep-trace --trace-file raw.txt --output parsed.json ./my_app

# Trace with custom arguments
strace-tui trace python3 -c "print('test')"

# Parse with all features
strace-tui parse existing_trace.txt --resolve --pretty --output result.json
```

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_test

# With output
cargo test -- --nocapture
```

### Example Programs

The project includes example programs to test the parser:

```bash
# Run example that generates various syscalls
cargo run --example syscall_test

# Generate and parse strace output
strace -o /tmp/test.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test
cargo run -- /tmp/test.txt --pretty | head -100
```

### Project Structure

```
src/
├── lib.rs              # Library entry point
├── main.rs             # CLI application
└── parser/
    ├── mod.rs          # Parser orchestration
    ├── types.rs        # Data structures
    ├── line_parser.rs  # Line-by-line parsing (nom)
    ├── backtrace_parser.rs  # Backtrace parsing
    └── resolver.rs     # addr2line integration
examples/
├── syscall_test.rs     # Syscall generation for testing
└── test_parser.rs      # Parser usage example
tests/
└── integration_test.rs # Integration tests
```

## Supported strace Patterns

The parser handles:

- ✅ Regular syscalls: `write(1, "hello", 5) = 5`
- ✅ Failed syscalls: `open("/foo", O_RDONLY) = -1 ENOENT (No such file or directory)`
- ✅ Unfinished: `read(3 <unfinished ...>`
- ✅ Resumed: `<... read resumed>, "data", 10) = 10`
- ✅ Signals: `--- SIGINT {si_signo=SIGINT, ...} ---`
- ✅ Exits: `+++ exited with 0 +++`
- ✅ Backtraces: ` > /usr/lib/libc.so.6(__write+0x14) [0x7f...]`
- ✅ Multi-process: PID prefixes with `-f` flag
- ✅ Hex return values: `mmap(...) = 0x7fff12345000`
- ✅ NULL values: `brk(NULL) = 0x...`

## Requirements

- Rust 1.91.1 or later (edition 2024)
- `addr2line` binary (for backtrace resolution feature)
- Linux (strace is Linux-specific)

## Roadmap

- [x] Core strace parser
- [x] JSON output
- [x] Backtrace resolution
- [x] Multi-process support
- [ ] TUI with ratatui
- [ ] Interactive filtering and search
- [ ] Process tree visualization
- [ ] Performance profiling features
- [ ] Real-time strace integration

## License

[Add your license here]

## Contributing

Contributions welcome! Please feel free to submit issues and pull requests.
