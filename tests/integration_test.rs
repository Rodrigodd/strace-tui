use strace_tui::{StraceParser, Addr2LineResolver};
use std::fs;

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
    
    let temp_file = "/tmp/test_strace.txt";
    fs::write(temp_file, sample).unwrap();
    
    let mut parser = StraceParser::new();
    let entries = parser.parse_file(temp_file).unwrap();
    
    assert!(entries.len() >= 4, "Should parse at least 4 entries");
    
    // Check first entry
    assert_eq!(entries[0].pid, 12345);
    assert_eq!(entries[0].syscall_name, "write");
    assert_eq!(entries[0].return_value, Some("6".to_string()));
    assert_eq!(entries[0].backtrace.len(), 1);
    assert_eq!(entries[0].backtrace[0].function, Some("__write".to_string()));
    
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
    
    fs::remove_file(temp_file).ok();
}

#[test]
fn test_unfinished_resumed() {
    let sample = r#"12345 10:20:30 read(0 <unfinished ...>
12346 10:20:30 write(1, "x", 1) = 1
12345 10:20:31 <... read resumed>, "data", 4) = 4
"#;
    
    let temp_file = "/tmp/test_unfinished.txt";
    fs::write(temp_file, sample).unwrap();
    
    let mut parser = StraceParser::new();
    let entries = parser.parse_file(temp_file).unwrap();
    
    // Should have merged unfinished+resumed into one entry
    let read_entry = entries.iter().find(|e| e.syscall_name == "read" && !e.is_unfinished);
    assert!(read_entry.is_some());
    assert_eq!(read_entry.unwrap().return_value, Some("4".to_string()));
    
    fs::remove_file(temp_file).ok();
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
