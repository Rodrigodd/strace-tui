# strace-tui

A terminal user interface (TUI) for visualizing and exploring strace output.

https://github.com/user-attachments/assets/a190090e-1e30-4692-9a20-5b2315cb7634

## Overview

**Supported features:**

- Parses common strace output and flags (`-tt -k -f -s 1024`) (also provides JSON output of parsed traces).
- Color-code syscall by type and error status.
- Allow dynamically filtering and search syscalls.
- Resolve strace stack-trace output (`strace -k`) to function names and source lines using `addr2line`.
- Visualize multithreaded and multiprocess traces with a graph for forks and clones.
- Search text in syscall arguments and results.

**Missing features:**

- Filter traces by process or thread ID.
- Copy syscall details to clipboard (specially because the TUI truncates a lot of info).
- Export filtered traces to file.
- Better handle gigantic Rust/C++ symbols (currently truncates middle of the symbol)

## Installation

Currently can only be installed from source:

```bash
cargo install --git https://github.com/Rodrigodd/trace-tui.git
```

## Usage

### Parse an existing strace file (TUI)

```bash
strace -o trace.txt -tt -k -f -s 1024 ls -la
strace-tui parse trace.txt
```

### Run strace and visualize

```bash
strace-tui trace ls -la
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
http://opensource.org/licenses/MIT)

at your option.
