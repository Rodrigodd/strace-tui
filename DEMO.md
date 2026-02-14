# strace-tui Demo

This document shows how to use strace-tui with examples.

## Quick Start

### 1. Build the project
```bash
cargo build --release
```

### 2. Generate a sample trace
```bash
# Build example program
cargo build --example syscall_test

# Run strace on it
strace -o trace.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test
```

### 3. Open in TUI
```bash
./target/release/strace-tui parse trace.txt
```

## TUI Demo Walkthrough

### Basic Navigation
1. **Arrow keys** or **j/k**: Move up/down through syscalls
2. **PageUp/PageDown**: Fast scroll
3. **Home/End** or **g/G**: Jump to first/last
4. **q**: Quit

### Exploring Syscalls
1. Press **Enter** on a syscall to expand it
2. See full arguments, return value, error details
3. Press **Enter** again to toggle backtrace (if available)
4. Press **x** to collapse
5. Press **e** to expand all, **c** to collapse all

### Understanding Colors
- **White**: Normal syscalls
- **Red**: Failed syscalls (errno set)
- **Yellow**: Signals (e.g., SIGSEGV)
- **Cyan**: Process exits
- **Green**: Resolved source locations
- **Gray**: Metadata (arguments, durations)
- **Magenta**: Backtrace headers

### Backtrace Resolution
1. Navigate to a syscall with a backtrace
2. Press **Enter** to expand the syscall
3. Press **Enter** again to expand and resolve the backtrace
4. Watch as addresses are resolved to source locations
5. Or press **r** to resolve just the current backtrace
6. Or press **R** to resolve all backtraces (slow!)

### Help Screen
- Press **?** to open the help overlay
- Shows all keybindings
- Press **?** or **Esc** to close

## JSON Mode Examples

### Basic JSON output
```bash
./target/release/strace-tui parse trace.txt --json > output.json
```

### Pretty-printed JSON
```bash
./target/release/strace-tui parse trace.txt --json --pretty
```

### With backtrace resolution
```bash
./target/release/strace-tui parse trace.txt --json --resolve --pretty > resolved.json
```

### Output to file
```bash
./target/release/strace-tui parse trace.txt --json --output result.json
```

## Trace Command Examples

### Trace any command
```bash
# Simple command
./target/release/strace-tui trace echo "Hello, World!"

# List files
./target/release/strace-tui trace ls -la

# Run a script
./target/release/strace-tui trace python3 script.py

# Multi-process command
./target/release/strace-tui trace bash -c "ls | wc -l"
```

### With options
```bash
# Keep the strace file
./target/release/strace-tui trace --keep-trace ls -la

# Custom trace file location
./target/release/strace-tui trace --trace-file my_trace.txt ./my_program

# JSON output instead of TUI
./target/release/strace-tui trace --json cat /etc/hostname
```

## Real-World Examples

### Debug a failing program
```bash
# Trace the failing command
./target/release/strace-tui trace ./buggy_program --arg value

# In TUI:
# 1. Look for red entries (errors)
# 2. Expand to see errno details
# 3. Check backtraces for where the error occurred
```

### Analyze file access
```bash
# Trace a program that reads/writes files
./target/release/strace-tui trace cat myfile.txt > /dev/null

# In TUI:
# 1. Look for open(), read(), write() syscalls
# 2. Expand to see file paths and sizes
# 3. Check return values to see what succeeded
```

### Profile syscall usage
```bash
# Export to JSON for analysis
./target/release/strace-tui trace --json --output profile.json my_app

# Analyze with jq
jq '.summary' profile.json
jq '.entries[] | select(.errno != null)' profile.json
jq '.entries[] | .syscall_name' profile.json | sort | uniq -c | sort -rn
```

### Multi-process debugging
```bash
# Trace a program that forks
./target/release/strace-tui trace bash -c "sleep 1 & wait"

# In TUI:
# 1. Notice different PIDs in brackets
# 2. See clone(), fork(), execve() calls
# 3. See how processes interact
```

## Tips & Tricks

### Quick Inspection
Start TUI, press 'e' to expand all, scroll through to get an overview, press 'c' to collapse all.

### Finding Errors
Look for red entries, or export JSON and grep:
```bash
./target/release/strace-tui parse trace.txt --json | jq '.entries[] | select(.errno != null)'
```

### Performance Analysis
Export with timestamps, analyze durations:
```bash
./target/release/strace-tui parse trace.txt --json | \
  jq '.entries[] | select(.duration != null) | {syscall: .syscall_name, duration: .duration}' | \
  jq -s 'sort_by(.duration) | reverse'
```

### Comparing Traces
```bash
# Trace two different runs
./target/release/strace-tui trace --json --output run1.json ./program --fast
./target/release/strace-tui trace --json --output run2.json ./program --slow

# Compare syscall counts
diff <(jq -r '.entries[] | .syscall_name' run1.json | sort | uniq -c) \
     <(jq -r '.entries[] | .syscall_name' run2.json | sort | uniq -c)
```

## Example Session

Here's a full example session:

```bash
# Build everything
cargo build --release --example syscall_test

# Generate trace
strace -o trace.txt -t -k -f -s 1024 ./target/debug/examples/syscall_test

# Open TUI
./target/release/strace-tui parse trace.txt

# In TUI:
# 1. Press 'j' a few times to navigate down
# 2. Press Enter to expand a syscall
# 3. Look at the arguments and return value
# 4. Press Enter again to expand the backtrace
# 5. See the resolved source locations
# 6. Press '?' to see help
# 7. Press 'e' to expand all entries
# 8. Press 'c' to collapse all
# 9. Press 'q' to quit

# Now try JSON mode
./target/release/strace-tui parse trace.txt --json --pretty | head -50

# Check the summary
./target/release/strace-tui parse trace.txt --json | jq '.summary'

# List all failed syscalls
./target/release/strace-tui parse trace.txt --json | \
  jq -r '.entries[] | select(.errno != null) | "\(.syscall_name): \(.errno.message)"'
```

## Troubleshooting

### "TUI error: ..."
Make sure your terminal is large enough (minimum 80x24). Try resizing.

### "Error running strace: ..."
Make sure `strace` is installed: `sudo apt install strace` (Debian/Ubuntu) or equivalent.

### "Resolved locations show ??"
System libraries often lack debug symbols. Install debug symbol packages or use on user programs.

### Slow backtrace resolution
This is expected - addr2line is slow. That's why resolution is on-demand in TUI mode. Use `-r` in JSON mode only when needed.

## Next Steps

- Read the [README](README.md) for full documentation
- Check [.github/copilot-instructions.md](.github/copilot-instructions.md) for development details
- Run the tests: `cargo test`
- Try tracing your own programs!
