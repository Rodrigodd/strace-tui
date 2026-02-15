mod parser;
mod tui;

use clap::{Parser as ClapParser, Subcommand};
use parser::{Addr2LineResolver, ParseErrorInfo, StraceOutput, StraceParser, SummaryStats};
use std::collections::HashSet;
use std::process::Command;
use tempfile::NamedTempFile;

#[derive(ClapParser)]
#[command(name = "strace-tui")]
#[command(about = "Parse strace output and visualize in a TUI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse an existing strace output file
    Parse {
        /// Input strace output file
        #[arg(value_name = "FILE")]
        input: String,

        /// Output JSON instead of opening TUI
        #[arg(long)]
        json: bool,

        /// Output file (only with --json)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Resolve backtraces using addr2line (only with --json)
        #[arg(short, long)]
        resolve: bool,

        /// Pretty print JSON output (only with --json)
        #[arg(short, long)]
        pretty: bool,
    },

    /// Run strace on a command and parse the output
    Trace {
        /// Command to trace
        #[arg(required = true)]
        command: Vec<String>,

        /// Output JSON instead of opening TUI
        #[arg(long)]
        json: bool,

        /// Output file (only with --json)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,

        /// Resolve backtraces using addr2line (only with --json)
        #[arg(short, long)]
        resolve: bool,

        /// Pretty print JSON output (only with --json)
        #[arg(short, long)]
        pretty: bool,

        /// Keep the strace output file (by default it's deleted)
        #[arg(short, long)]
        keep_trace: bool,

        /// Path for strace output (default: temp file)
        #[arg(long, value_name = "FILE")]
        trace_file: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse {
            input,
            json,
            output,
            resolve,
            pretty,
        } => {
            if json {
                parse_file_json(&input, output, resolve, pretty);
            } else {
                parse_file_tui(&input);
            }
        }
        Commands::Trace {
            command,
            json,
            output,
            resolve,
            pretty,
            keep_trace,
            trace_file,
        } => {
            let trace_path = run_strace(command, trace_file);

            if json {
                parse_file_json(&trace_path, output, resolve, pretty);
            } else {
                parse_file_tui(&trace_path);
            }

            // Clean up trace file unless keep_trace is set
            if !keep_trace {
                std::fs::remove_file(&trace_path).ok();
            } else {
                eprintln!("Trace file kept at: {}", trace_path);
            }
        }
    }
}

fn parse_file_tui(input: &str) {
    // Parse the strace output
    let mut parser = StraceParser::new();
    let entries = match parser.parse_file(input) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("Error parsing file: {}", err);
            std::process::exit(1);
        }
    };

    if entries.is_empty() {
        eprintln!("No syscalls found in trace file");
        std::process::exit(1);
    }

    // Generate summary
    let summary = generate_summary(&entries);

    // Run TUI
    if let Err(e) = tui::run_tui(entries, summary, Some(input.to_string())) {
        eprintln!("TUI error: {}", e);
        std::process::exit(1);
    }
}

fn parse_file_json(input: &str, output: Option<String>, resolve: bool, pretty: bool) {
    // Parse the strace output
    let mut parser = StraceParser::new();
    let mut entries = match parser.parse_file(input) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("Error parsing file: {}", err);
            std::process::exit(1);
        }
    };

    // Resolve backtraces if requested
    if resolve {
        eprintln!("Resolving backtraces with addr2line...");
        let mut resolver = Addr2LineResolver::new();

        for entry in entries.iter_mut() {
            if !entry.backtrace.is_empty() {
                let _ = resolver.resolve_frames(&mut entry.backtrace);
            }
        }

        eprintln!("Resolved {} unique addresses", resolver.cache_size());
    }

    // Generate and output
    output_results(entries, parser.errors, output, pretty);
}

fn run_strace(command: Vec<String>, trace_file: Option<String>) -> String {
    if command.is_empty() {
        eprintln!("Error: No command specified");
        std::process::exit(1);
    }

    // Determine trace file path - use user-specified or create temp file
    let trace_path = if let Some(path) = trace_file {
        path
    } else {
        // Create a temp file with a meaningful name
        let temp = NamedTempFile::with_prefix("strace-tui-")
            .expect("Failed to create temp file");
        // Keep the temp file around by persisting it
        temp.keep().expect("Failed to persist temp file").1
            .to_str().unwrap().to_string()
    };

    eprintln!("Running strace on: {}", command.join(" "));
    eprintln!("Trace output: {}", trace_path);

    // Run strace
    let status = Command::new("strace")
        .arg("-o")
        .arg(&trace_path)
        .arg("-t") // timestamps
        .arg("-k") // backtraces
        .arg("-f") // follow forks
        .arg("-s")
        .arg("1024") // string capture size
        .args(&command)
        .status();

    let status = match status {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error running strace: {}", e);
            eprintln!("Make sure strace is installed and in PATH");
            std::process::exit(1);
        }
    };

    if !status.success() {
        eprintln!("Warning: strace exited with status: {}", status);
    }

    // Check if trace file exists
    if !std::path::Path::new(&trace_path).exists() {
        eprintln!("Error: Trace file not created: {}", trace_path);
        std::process::exit(1);
    }

    trace_path
}

fn output_results(
    entries: Vec<parser::SyscallEntry>,
    errors: Vec<(usize, parser::ParseError)>,
    output_file: Option<String>,
    pretty: bool,
) {
    // Generate summary stats
    let summary = generate_summary(&entries);

    // Convert parse errors
    let error_info: Vec<ParseErrorInfo> = errors
        .iter()
        .map(|(line, err)| ParseErrorInfo {
            line_number: *line,
            message: err.to_string(),
        })
        .collect();

    let output = StraceOutput {
        entries,
        summary,
        errors: error_info,
    };

    // Serialize to JSON
    let json = if pretty {
        serde_json::to_string_pretty(&output)
    } else {
        serde_json::to_string(&output)
    };

    let json = match json {
        Ok(j) => j,
        Err(err) => {
            eprintln!("Error serializing to JSON: {}", err);
            std::process::exit(1);
        }
    };

    // Write output
    if let Some(output_path) = output_file {
        if let Err(err) = std::fs::write(&output_path, json) {
            eprintln!("Error writing to {}: {}", output_path, err);
            std::process::exit(1);
        }
        eprintln!("Output written to {}", output_path);
    } else {
        println!("{}", json);
    }
}

fn generate_summary(entries: &[parser::SyscallEntry]) -> SummaryStats {
    let mut unique_pids = HashSet::new();
    let mut failed = 0;
    let mut signals = 0;
    let mut total_duration = 0.0;

    for entry in entries {
        unique_pids.insert(entry.pid);

        if entry.errno.is_some() {
            failed += 1;
        }

        if entry.signal.is_some() {
            signals += 1;
        }

        if let Some(dur) = entry.duration {
            total_duration += dur;
        }
    }

    let unique_pids: Vec<u32> = unique_pids.into_iter().collect();

    SummaryStats {
        total_syscalls: entries.len(),
        failed_syscalls: failed,
        signals,
        unique_pids,
        total_duration: if total_duration > 0.0 {
            Some(total_duration)
        } else {
            None
        },
    }
}
