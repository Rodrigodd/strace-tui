use strace_tui::parser::StraceParser;

fn main() {
    let mut parser = StraceParser::new();

    match parser.parse_file("/tmp/strace_output.txt") {
        Ok(entries) => {
            println!("Successfully parsed {} syscall entries", entries.len());
            println!("\nFirst 10 entries:");
            for (i, entry) in entries.iter().take(10).enumerate() {
                println!(
                    "{}. PID {} @ {}: {} ({})",
                    i + 1,
                    entry.pid,
                    entry.timestamp,
                    entry.syscall_name,
                    if entry.backtrace.is_empty() {
                        "no backtrace".to_string()
                    } else {
                        format!("{} frames", entry.backtrace.len())
                    }
                );
            }

            println!("\nParser errors: {}", parser.errors.len());
            for (line, err) in parser.errors.iter().take(5) {
                println!("  Line {}: {}", line, err);
            }
        }
        Err(e) => {
            eprintln!("Failed to parse: {}", e);
        }
    }
}
