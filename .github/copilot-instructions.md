# Copilot Instructions for strace-tui

## Project Overview

A terminal user interface (TUI) for strace, built in Rust. Currently implements a comprehensive parser for strace output that converts system call traces to structured JSON data. The TUI visualization component is planned for future development.

## Build, Test, and Lint

### Build
```bash
cargo build
cargo build --release
```

### Run
```bash
# Parse strace output to JSON
cargo run -- <strace-file> [options]

# With options
cargo run -- /tmp/strace.txt --pretty
cargo run -- /tmp/strace.txt --resolve --output parsed.json

# Run example programs
cargo run --example syscall_test
cargo run --example test_parser
```

### Test
```bash
# Run all tests
cargo test

# Run a single test
cargo test test_name

# Run tests in a specific module
cargo test parser::

# Run integration tests
cargo test --test integration_test
```

### Lint
```bash
# Check code without building
cargo check

# Run clippy for linting
cargo clippy
cargo clippy -- -D warnings  # Treat warnings as errors

# Format code
cargo fmt
cargo fmt -- --check  # Check formatting without modifying files
```

## Architecture

### Current Structure
- `src/lib.rs` - Library entry point, re-exports parser module
- `src/main.rs` - CLI application for parsing strace output
- `src/parser/` - Core parsing logic
  - `mod.rs` - Parser orchestration and multi-line handling
  - `types.rs` - Data structures (SyscallEntry, BacktraceFrame, etc.)
  - `line_parser.rs` - Parses individual strace lines using nom
  - `backtrace_parser.rs` - Parses stack trace lines from `-k` flag
  - `resolver.rs` - Resolves addresses to source locations via addr2line
- `examples/` - Example programs
  - `syscall_test.rs` - Generates various syscalls for testing
  - `test_parser.rs` - Demonstrates parser usage
- `tests/` - Integration tests

### Parser Flow
1. **Input**: strace output file (from `strace -o out.txt -t -k -f -s 1024 <cmd>`)
2. **Line-by-line parsing**: Each line is classified as syscall, backtrace, signal, or exit
3. **State management**: Handles `<unfinished ...>` and `<... resumed>` patterns across lines
4. **Backtrace assembly**: Groups consecutive backtrace lines with their syscall
5. **Address resolution** (optional): Shells out to `addr2line` to resolve addresses
6. **Output**: Structured JSON with entries, summary statistics, and parse errors

### Key Data Structures
- **SyscallEntry**: Represents a single syscall with PID, timestamp, arguments, return value, errno, backtrace, and flags
- **BacktraceFrame**: Stack frame with binary path, function name, address, and optional resolved source location
- **StraceParser**: Stateful parser that accumulates entries and handles multi-line constructs

## Key Conventions

### Rust Edition
The project uses Rust edition 2024 as specified in Cargo.toml.

### Error Handling
- Parser collects all errors during parsing rather than failing fast
- Errors are returned in the final output with line numbers
- Individual address resolution failures don't stop the overall process

### Code Style
Follow standard Rust conventions:
- Use `cargo fmt` for consistent formatting
- Address all `cargo clippy` warnings
- Use idiomatic Rust patterns (Result types, pattern matching, etc.)

## Working with strace

### Generating Test Data
```bash
# Run strace with required flags
strace -o out.txt -t -k -f -s 1024 <command>

# Flags explained:
# -o out.txt : Write to file instead of stderr
# -t : Include timestamps (HH:MM:SS format)
# -k : Include kernel backtraces
# -f : Follow forks (trace child processes)
# -s 1024 : Capture up to 1024 bytes of string arguments
```

### strace Output Patterns
The parser handles:
- **Regular syscalls**: `PID TIME syscall(args) = retval`
- **Failed syscalls**: `... = -1 ERRNO (Error message)`
- **Unfinished syscalls**: `... <unfinished ...>` (async operations)
- **Resumed syscalls**: `<... syscall resumed> ...) = retval`
- **Signals**: `--- SIGNAL {...} ---`
- **Process exit**: `+++ exited with N +++`
- **Backtraces**: ` > /path/to/binary(function+offset) [0xaddr]`
- **Multi-process traces**: PID prefix on each line

### Important Notes
- strace outputs to stderr by default, not stdout
- Backtrace addresses are relative to the binary's load address
- System libraries often lack debug symbols, so addr2line may fail for them
- Platform-specific: strace is Linux-specific

## Development Tips

### Adding New Syscall Patterns
When supporting new syscall formats:
1. Add test cases in `src/parser/line_parser.rs` tests
2. Update the nom parser combinators in `parse_strace_line()`
3. Handle edge cases in `parse_arguments()` if the pattern is complex

### Testing Parser Changes
1. Use `examples/syscall_test.rs` to generate real strace output
2. Run `strace -o /tmp/test.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test`
3. Parse it: `cargo run -- /tmp/test.txt --pretty | head -100`
4. Verify specific patterns with grep: `cat /tmp/test.txt | grep -A 5 "unfinished"`

### Performance Considerations
- Parser uses streaming I/O (BufReader) to handle large trace files
- addr2line resolution is cached to avoid redundant lookups
- For very large files (millions of syscalls), consider increasing the buffer size

## Future TUI Development

When implementing the TUI visualization:
- Use `ratatui` crate (modern, actively maintained)
- Handle terminal resize events
- Ensure proper cleanup on exit (restore terminal state)
- Consider async runtime for non-blocking I/O
- Design for filtering, searching, and navigation of syscall traces
- Show process tree visualization for multi-process traces
- Highlight failed syscalls and signals

