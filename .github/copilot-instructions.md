# Copilot Instructions for strace-tui

## Project Overview

strace-tui is a terminal user interface (TUI) for visualizing and exploring strace output. It parses strace output files and provides an interactive interface for browsing syscalls, viewing details, and resolving backtraces.

**Status**: ✅ Complete - Full TUI implementation with interactive navigation  
**Language**: Rust (Edition 2024)  
**Main Dependencies**: nom (parsing), ratatui (TUI), crossterm (terminal), serde (JSON), clap (CLI)

## Quick Commands

```bash
# Build
cargo build --release

# Run tests
cargo test

# TUI mode (default)
./target/release/strace-tui parse trace.txt
./target/release/strace-tui trace ls -la

# JSON mode
./target/release/strace-tui parse trace.txt --json --pretty
./target/release/strace-tui trace --json echo "test"

# Generate test trace
cargo build --example syscall_test
strace -o trace.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test
```

## Architecture

### Overview
The project has three main components:

1. **Parser** (`src/parser/`) - Parses strace output into structured data
2. **TUI** (`src/tui/`) - Interactive terminal interface for exploration
3. **CLI** (`src/main.rs`) - Command-line interface with parse/trace subcommands

### Mode Selection
- **Default**: Interactive TUI for visual exploration
- **JSON mode**: Use `--json` flag for programmatic access

### Module Structure

```
src/
├── main.rs              # CLI entry point, subcommand handling
├── lib.rs               # Library interface
├── parser/
│   ├── mod.rs           # Parser orchestration, multi-line handling
│   ├── types.rs         # Data structures (SyscallEntry, etc.)
│   ├── line_parser.rs   # nom-based line parsing
│   ├── backtrace_parser.rs  # Backtrace parsing
│   └── resolver.rs      # addr2line integration
└── tui/
    ├── mod.rs           # TUI entry point, terminal setup
    ├── app.rs           # Application state and event handling
    ├── ui.rs            # Rendering logic
    └── events.rs        # Keyboard input handling
```

## Key Features

### Parser
- **Input format**: `strace -o file.txt -t -k -f -s 1024 <cmd>`
- **Supports**: All syscall patterns, signals, exits, multi-process traces, kernel backtraces
- **Parser**: nom combinator-based, handles `<unfinished ...>` and `<... resumed>` patterns
- **Output**: Structured `SyscallEntry` objects with full metadata

### TUI
- **Navigation**: Arrow keys, vim-style (j/k), page up/down, home/end
- **Expansion**: Enter to expand syscall details and toggle backtraces
- **Colors**: Red (errors), yellow (signals), cyan (exits), green (resolved addresses)
- **Performance**: Lazy backtrace resolution (only on expand), smooth scrolling
- **Help**: Press `?` for keybindings overlay

### addr2line Integration
- **On-demand**: Backtraces resolved when expanded in TUI
- **Batch mode**: Pre-resolve all with `-r` in JSON mode
- **Caching**: Addresses cached to avoid redundant lookups
- **Method**: Shells out to system `addr2line` binary

## Data Structures

```rust
// Main entry type
pub struct SyscallEntry {
    pub pid: u32,
    pub timestamp: String,
    pub syscall_name: String,
    pub arguments: String,
    pub return_value: Option<String>,
    pub errno: Option<ErrnoInfo>,
    pub duration: Option<f64>,
    pub backtrace: Vec<BacktraceFrame>,
    pub is_unfinished: bool,
    pub is_resumed: bool,
    pub signal: Option<SignalInfo>,
    pub exit_info: Option<ExitInfo>,
}

// Backtrace frame
pub struct BacktraceFrame {
    pub binary: String,
    pub function: Option<String>,
    pub offset: Option<String>,
    pub address: String,
    pub resolved: Option<ResolvedLocation>,
}

// TUI state
pub struct App {
    pub entries: Vec<SyscallEntry>,
    pub resolver: Addr2LineResolver,
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub expanded_items: HashSet<usize>,
    pub expanded_backtraces: HashSet<usize>,
    pub should_quit: bool,
    pub show_help: bool,
}
```

## strace Output Patterns

The parser handles all major strace patterns:

### Regular syscall
```
12345 10:20:30 write(1, "hello\n", 6) = 6
```

### With error
```
12345 10:20:30 open("/no/file", O_RDONLY) = -1 ENOENT (No such file or directory)
```

### Unfinished/resumed (multi-line async)
```
12345 10:20:30 read(3, <unfinished ...>
12346 10:20:31 write(1, "test", 4) = 4
12345 10:20:32 <... read resumed> "data", 1024) = 4
```

### Signal
```
12345 10:20:30 --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, ...} ---
```

### Exit
```
12345 10:20:30 +++ exited with 0 +++
12346 10:20:31 +++ killed by SIGKILL +++
```

### Backtrace (multi-line)
```
12345 10:20:30 write(1, "test", 4) = 4
 > /usr/lib/libc.so.6(__write+0x14) [0x10e53e]
 > /home/user/program(main+0x2a) [0x401234]
```

## Parser Flow

1. **Line-by-line parsing** (`src/parser/mod.rs:parse_lines()`)
   - Read each line
   - Check if it's a backtrace line (starts with ` > `)
   - If backtrace: add to pending backtrace buffer
   - If syscall: parse with `line_parser.rs`, attach pending backtrace

2. **Syscall parsing** (`src/parser/line_parser.rs:parse_strace_line()`)
   - Extract PID and timestamp
   - Parse syscall name
   - Parse arguments (handling nested parentheses)
   - Check for `<unfinished ...>` pattern
   - Parse return value and errno
   - Handle special cases (signals, exits, resumed)

3. **Unfinished/resumed handling**
   - Store unfinished entries in `HashMap<u32, SyscallEntry>` keyed by PID
   - When `<... resumed>` found, merge with stored entry
   - Preserve original timestamp from unfinished line

4. **Backtrace parsing** (`src/parser/backtrace_parser.rs`)
   - Parse binary path, function name, offset, address
   - Multiple formats supported (with/without function, with/without offset)

5. **Resolution** (`src/parser/resolver.rs`)
   - Call `addr2line -e <binary> -f -C <address>`
   - Parse output: function name on line 1, file:line on line 2
   - Cache results for performance

## TUI Implementation

### Event Loop (src/tui/mod.rs)
1. Setup terminal (raw mode, alternate screen)
2. Create App state with parsed entries
3. Loop:
   - Draw UI (`ui::draw()`)
   - Poll for keyboard events (100ms timeout)
   - Handle events (`app.handle_event()`)
   - Check quit flag
4. Cleanup terminal

### Drawing (src/tui/ui.rs)
- **Header**: File name, summary stats (syscalls, errors, PIDs, signals)
- **Main list**: Tree-style expandable items
  - Main syscall line with arrow (▶/▼)
  - Expanded details (arguments, return value, error, duration, signal, exit)
  - Backtrace section (expandable, resolves on-demand)
- **Footer**: Keybinding help
- **Help overlay**: Full help on `?` key (centered, 60x80%)

### Navigation (src/tui/app.rs)
- Track `selected_index` (which syscall)
- Track `expanded_items` (which syscalls are expanded)
- Track `expanded_backtraces` (which backtraces are visible)
- Auto-scroll to keep selection visible
- Enter: Expand/toggle backtrace
- x: Collapse current
- e/c: Expand/collapse all

## Development Guidelines

### Code Style
- Use `cargo fmt` for formatting
- Follow Rust naming conventions (snake_case for functions, PascalCase for types)
- Add comments for complex parsing logic
- Keep functions focused and small

### Testing
- Unit tests in each module (`#[cfg(test)] mod tests`)
- Integration tests in `tests/` directory
- Test all parser patterns (see `line_parser.rs` tests)
- Use `pretty_assertions` for better diff output

### Error Handling
- Parser: Collect errors, don't fail on first error
- CLI: Exit with code 1 on errors, print to stderr
- TUI: Graceful degradation (missing data shows as empty)

### Performance Considerations
- **Lazy resolution**: Only resolve backtraces when expanded (addr2line is slow ~50-100ms per address)
- **Caching**: Resolver caches all lookups in HashMap
- **Streaming**: Parser reads line-by-line, doesn't load entire file
- **Virtual scrolling**: TUI loads all entries but only renders visible region

## Common Tasks

### Adding a new syscall pattern
1. Add test case in `line_parser.rs::tests`
2. Update `parse_syscall_name()` or add special case parsing
3. Update `types.rs` if new data needs to be captured
4. Run tests: `cargo test parser::line_parser::tests`

### Modifying TUI layout
1. Update `ui.rs::draw_list()` for main list rendering
2. Update `ui.rs::draw_header()` or `draw_footer()` for top/bottom
3. Test with: `cargo run -- parse trace.txt`

### Adding TUI keybinding
1. Add handler in `app.rs::handle_event()`
2. Update help text in `ui.rs::draw_help()`
3. Update footer in `ui.rs::draw_footer()`

## Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_parse_simple_syscall

# Run with output
cargo test -- --nocapture

# Generate test data
cargo build --example syscall_test
strace -o trace.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test

# Test TUI (use 'q' to quit)
cargo run -- parse trace.txt

# Test JSON output
cargo run -- parse trace.txt --json | jq '.summary'
```

## Dependencies

```toml
[dependencies]
nom = "7.1"                    # Parser combinators
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"             # JSON serialization
clap = { version = "4.5", features = ["derive"] }
thiserror = "2.0"              # Error handling
ratatui = "0.28"               # TUI framework
crossterm = "0.28"             # Terminal handling

[dev-dependencies]
pretty_assertions = "1.4"      # Better test diffs
```

## Files of Interest

- `src/parser/line_parser.rs` (12K chars) - Core parsing logic with nom
- `src/tui/ui.rs` (9K chars) - TUI rendering with ratatui
- `src/tui/app.rs` (5K chars) - TUI state management
- `src/parser/mod.rs` (5K chars) - Parser orchestration
- `src/main.rs` (13K chars) - CLI entry point
- `tests/integration_test.rs` - End-to-end CLI tests
- `examples/syscall_test.rs` - Generates realistic strace output
