use std::io::Write;
use strace_tui::{Addr2LineResolver, StraceParser};
use tempfile::NamedTempFile;

#[test]
fn test_parse_example_strace() {
    // Create a sample strace output
    let sample = r#"12345 10:20:30 write(1, "hello\n", 6) = 6
 > /usr/lib/libc.so.6(__write+0x14) [0x10e53e]
12345 10:20:31 read(0, "input", 5) = 5
12345 10:20:32 close(1) = 0
12345 10:20:33 --- SIGINT {si_signo=SIGINT, si_code=SI_USER, si_pid=123, si_uid=1000} ---
12345 10:20:34 +++ exited with 0 +++
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(sample.as_bytes()).unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    let mut parser = StraceParser::new();
    let entries = parser.parse_file(temp_path).unwrap();

    assert!(entries.len() >= 4, "Should parse at least 4 entries");

    // Check first entry
    assert_eq!(entries[0].pid, 12345);
    assert_eq!(entries[0].syscall_name, "write");
    assert_eq!(entries[0].return_value, Some("6".to_string()));
    assert_eq!(entries[0].backtrace.len(), 1);
    assert_eq!(
        entries[0].backtrace[0].function,
        Some("__write".to_string())
    );

    // Check signal entry
    let signal_entry = entries.iter().find(|e| e.signal.is_some());
    assert!(signal_entry.is_some());
    let signal = signal_entry.unwrap().signal.as_ref().unwrap();
    assert_eq!(signal.signal_name, "SIGINT");

    // Check exit entry
    let exit_entry = entries.iter().find(|e| e.exit_info.is_some());
    assert!(exit_entry.is_some());
    let exit_info = exit_entry.unwrap().exit_info.as_ref().unwrap();
    assert_eq!(exit_info.code, 0);
}

#[test]
fn test_unfinished_resumed() {
    let sample = r#"12345 10:20:30 read(0 <unfinished ...>
12346 10:20:30 write(1, "x", 1) = 1
12345 10:20:31 <... read resumed>, "data", 4) = 4
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(sample.as_bytes()).unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    let mut parser = StraceParser::new();
    let entries = parser.parse_file(temp_path).unwrap();

    // Should have merged unfinished+resumed into one entry
    let read_entry = entries
        .iter()
        .find(|e| e.syscall_name == "read" && !e.is_unfinished);
    assert!(read_entry.is_some());
    assert_eq!(read_entry.unwrap().return_value, Some("4".to_string()));
}

#[test]
fn test_addr2line_resolver() {
    let mut resolver = Addr2LineResolver::new();

    // Create a dummy frame
    let mut frame = strace_tui::BacktraceFrame {
        binary: "/bin/ls".to_string(),
        function: Some("main".to_string()),
        offset: Some("0x10".to_string()),
        address: "0x1234".to_string(),
        resolved: None,
    };

    // Try to resolve - should not error even if it fails
    let result = resolver.resolve_frame(&mut frame);
    assert!(result.is_ok());

    // Check caching works
    assert_eq!(resolver.cache_size(), 1);
}

#[test]
fn test_parse_no_pid_format() {
    // Test parsing strace output without PIDs (strace without -f)
    let sample = r#"23:14:48 execve("/usr/bin/echo", ["echo", "test"], 0x7ffea15c5fd8 /* 42 vars */) = 0
23:14:48 brk(NULL) = 0x55772af19000
23:14:48 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
23:14:48 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
23:14:48 close(3) = 0
23:14:48 write(1, "test\n", 5) = 5
23:14:48 +++ exited with 0 +++
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(sample.as_bytes()).unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    let mut parser = StraceParser::new();
    let entries = parser.parse_file(temp_path).unwrap();

    assert!(entries.len() >= 6, "Should parse at least 6 entries");

    // All entries should have PID 0 (no PID in format)
    for entry in &entries {
        assert_eq!(entry.pid, 0, "Entries without PID should have PID 0");
    }

    // Check first syscall
    assert_eq!(entries[0].syscall_name, "execve");
    assert_eq!(entries[0].timestamp, "23:14:48");
    assert_eq!(entries[0].return_value, Some("0".to_string()));

    // Check syscall with error
    let access_entry = entries.iter().find(|e| e.syscall_name == "access");
    assert!(access_entry.is_some());
    assert!(access_entry.unwrap().errno.is_some());

    // Check exit entry
    let exit_entry = entries.iter().find(|e| e.exit_info.is_some());
    assert!(exit_entry.is_some());
    assert_eq!(exit_entry.unwrap().exit_info.as_ref().unwrap().code, 0);
}

#[test]
fn test_cli_parse_subcommand() {
    use std::process::Command;

    // Create a sample trace file
    let sample = r#"12345 10:20:30 write(1, "test\n", 5) = 5
 > /usr/lib/libc.so.6(__write+0x14) [0x10e53e]
12345 10:20:31 close(1) = 0
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(sample.as_bytes()).unwrap();
    let temp_path = temp_file.path().to_str().unwrap();

    // Build first to ensure binary exists
    Command::new("cargo")
        .args(&["build", "--quiet"])
        .status()
        .expect("Failed to build");

    // Run the parse subcommand using the built binary
    let output = Command::new("./target/debug/strace-tui")
        .args(&["parse", temp_path, "--json"])
        .output()
        .expect("Failed to run parse command");

    assert!(output.status.success(), "parse command should succeed");

    // Verify it's valid JSON
    let json_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("Output should be valid JSON");

    // Check it has the expected structure
    assert!(parsed["entries"].is_array());
    assert!(parsed["summary"].is_object());
}

#[test]
fn test_cli_trace_subcommand() {
    use std::process::Command;

    // Build first to ensure binary exists
    Command::new("cargo")
        .args(&["build", "--quiet"])
        .status()
        .expect("Failed to build");

    // Create temp file for output
    let temp_output = NamedTempFile::new().unwrap();
    let output_path = temp_output.path().to_str().unwrap();

    // Run the trace subcommand with output to file to avoid mixing traced program output with JSON
    let output = Command::new("./target/debug/strace-tui")
        .args(&["trace", "--json", "--output", output_path, "echo", "test"])
        .output()
        .expect("Failed to run trace command");

    // Command should succeed
    assert!(output.status.success(), "trace command should succeed");

    // Read the output file
    let json_str = std::fs::read_to_string(output_path).expect("Failed to read output file");

    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("Output should be valid JSON");

    // Check it has the expected structure
    assert!(parsed["entries"].is_array());
    assert!(parsed["summary"].is_object());

    // Should have some syscalls
    let syscall_count = parsed["summary"]["total_syscalls"].as_u64().unwrap();
    assert!(syscall_count > 0, "Should trace at least one syscall");
}
