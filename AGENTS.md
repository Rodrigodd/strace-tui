# strace-tui

Terminal UI for exploring strace output: parses a trace file (or traces a command) and lets you browse syscalls, expand details, and resolve backtraces. Rust (Edition 2024), using nom, ratatui/crossterm, clap, serde, and the `addr2line` crate.

## Commands

```bash
cargo build --release
cargo test
cargo clippy --all-targets --all-features -- -D warnings

./target/release/strace-tui parse trace.txt          # TUI
./target/release/strace-tui trace ls -la             # trace a command, open TUI
./target/release/strace-tui parse trace.txt --json --pretty
./target/release/strace-tui trace --json -r echo hi  # -r: pre-resolve backtraces

# Generate a test trace
cargo build --example syscall_test
strace -o trace.txt -tt -T -k -f -s 1024 ./target/debug/examples/syscall_test
```

## Architecture

```
src/
├── main.rs              # CLI: parse/trace subcommands, JSON output
├── lib.rs               # Library interface
├── parser/
│   ├── mod.rs           # Line-by-line orchestration, backtrace/unfinished handling
│   ├── types.rs         # SyscallEntry and related types
│   ├── line_parser.rs   # nom parser for a single strace line
│   ├── args.rs          # Argument splitting, -y fd annotations, fd/path/array args
│   ├── fd_tracker.rs    # analyze_files(): fd lifetimes and resources across the trace
│   ├── backtrace_parser.rs  # ` > binary(func+off) [addr]` lines
│   └── resolver.rs      # Backtrace resolution via addr2line crate, cached
└── tui/
    ├── mod.rs           # Terminal setup, event loop
    ├── app.rs           # State, DisplayLine tree, key handling
    ├── ui.rs            # Rendering, help/filter modals
    ├── process_graph.rs # Process lifetime / fork / wait graph
    ├── process_list.rs  # Processes tab: per-PID summaries, own display lines/search
    ├── file_list.rs     # Files tab: resource → fd lifetime → access tree
    └── syscall_colors.rs # Category-based syscall colors
```

Non-obvious details:
- Backtrace lines (` > ...`) follow their syscall line and get attached to it.
- `<unfinished ...>` entries are stored per PID and merged when the matching `<... resumed>` line arrives. The merged entry keeps the original timestamp.
- The TUI flattens everything into a `Vec<DisplayLine>` built by `rebuild_display_lines()`. Each line carries a `TreePrefix` for the │ ├ └ drawing.
- `selected_line` indexes `display_lines`, not the syscall list.
- Hidden syscalls (`hidden_syscalls`) are skipped unless `show_hidden` is on, which shows them as "ghost" lines.
- Three tabs (`App::active_tab`, keys `1`/`2`/`3` or click): Syscalls uses the `App` fields above; Processes and Files keep their own state in `ProcessTabState`/`FileTabState` and return `JumpToEntry` actions for `App::jump_to_entry()`.
- `trace` runs strace with `-yy`, so fds are annotated like `3</etc/passwd>` or `4<pipe:[123]>`. The annotation of a return value goes to `SyscallEntry::return_annotation`. Use the `args.rs` helpers (`split_arguments`, `parse_fd_arg`, ...) instead of splitting arguments by hand, since annotations can contain `,`, `)` and `->`.
- `analyze_files()` (in `App::files`, and `files` in JSON) follows fds through dup, fork/clone (shared with `CLONE_FILES`), close-on-exec and exit. A `FileAccess` points to the first half of an unfinished/resumed pair. `FileAnalysis::refs()` maps each entry's arguments (or return value, `arg_idx: None`) to resources, and Enter on them jumps to the Files tab.
- The Files tab hides accesses of hidden syscalls/processes. `App::rebuild_display_lines()` marks it dirty, and `App::sync_files_tab()` rebuilds it lazily.
- Hidden processes live in `ProcessTabState::hidden_pids` (each tab has its own ghost mode); the Syscalls tab checks them through `App::is_entry_hidden()`.

## Common Tasks

**Adding a syscall pattern**
1. Add a test in `line_parser.rs` tests
2. Update the parser in `line_parser.rs`
3. Update `types.rs` if new data needs to be captured
4. `cargo test parser::line_parser::tests`

**Changing the TUI layout**
1. Add or change a `DisplayLine` variant in `app.rs`
2. Emit it in `rebuild_display_lines()`
3. Render it in `ui.rs::draw_list()`

**Adding a keybinding**
1. Handle it in `app.rs::handle_event()`
2. Update help text in `ui.rs::draw_help()`
3. Update the footer in `ui.rs::draw_footer()`

## Guidelines

- Resolve backtraces lazily (only when expanded); resolution is slow and results are cached.
- Parser: collect errors instead of failing on the first one.
- TUI: missing data should render as empty, never panic.
- Unit tests go in each module; end-to-end CLI tests go in `tests/integration_test.rs`. Use `pretty_assertions`.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/): `<type>(<scope>): <description>`

- **Description**: imperative mood, lowercase, no trailing period (e.g. `fix(parser): handle extra output in resumed syscall`)
- **Type** (required), one of:
  - `feat` - new user-visible feature or behavior
  - `fix` - bug fix
  - `perf` - performance or binary size improvement
  - `refactor` - code change with no behavior change
  - `docs` - documentation only (README, AGENTS.md, comments)
  - `test` - adding or updating tests only
  - `build` - Cargo.toml/Cargo.lock, version bumps, build profile
  - `chore` - maintenance: dependency updates, `cargo fmt`, clippy fixes, file cleanup
- **Scope** (optional), strictly one of:
  - `parser` - `src/parser/` except the resolver (line/backtrace parsing, types, unfinished/resumed merging)
  - `resolver` - `src/parser/resolver.rs` (backtrace resolution)
  - `tui` - `src/tui/` except the process graph (app state, rendering, keybindings, search, filters)
  - `process_graph` - `src/tui/process_graph.rs` (process lifetime/fork/wait graph)
  - `cli` - `src/main.rs` (subcommands, flags, JSON output)
- Leave out the scope when a change spans several scopes or fits none of them (e.g. `examples/`, `tests/`, dependencies). Ask the user before inventing new scopes.
- Breaking changes: add `!` after the type/scope (`feat(cli)!: ...`) and a `BREAKING CHANGE:` footer. Never mark TUI changes as breaking.
