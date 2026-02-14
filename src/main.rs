mod parser;

use clap::{Parser as ClapParser, Subcommand};
use parser::{Addr2LineResolver, StraceParser, StraceOutput, SummaryStats, ParseErrorInfo};
use std::collections::HashSet;
use std::process::Command;

#[derive(ClapParser)]
#[command(name = "strace-tui")]
#[command(about = "Parse strace output and convert to structured data", long_about = None)]
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
        
        /// Output file (default: stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
        
        /// Resolve backtraces using addr2line
        #[arg(short, long)]
        resolve: bool,
        
        /// Pretty print JSON output
        #[arg(short, long)]
        pretty: bool,
    },
    
    /// Run strace on a command and parse the output
    Trace {
        /// Command to trace
        #[arg(required = true)]
        command: Vec<String>,
        
        /// Output file (default: stdout)
        #[arg(short, long, value_name = "FILE")]
        output: Option<String>,
        
        /// Resolve backtraces using addr2line
        #[arg(short, long)]
        resolve: bool,
        
        /// Pretty print JSON output
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
        Commands::Parse { input, output, resolve, pretty } => {
            parse_file(&input, output, resolve, pretty);
        }
        Commands::Trace { command, output, resolve, pretty, keep_trace, trace_file } => {
            trace_command(command, output, resolve, pretty, keep_trace, trace_file);
        }
    }
}

fn parse_file(input: &str, output: Option<String>, resolve: bool, pretty: bool) {
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

fn trace_command(
    command: Vec<String>,
    output: Option<String>,
    resolve: bool,
    pretty: bool,
    keep_trace: bool,
    trace_file: Option<String>,
) {
    if command.is_empty() {
        eprintln!("Error: No command specified");
        std::process::exit(1);
    }
    
    // Determine trace file path
    let trace_path = trace_file.unwrap_or_else(|| {
        format!("/tmp/strace-tui-{}.txt", std::process::id())
    });
    
    eprintln!("Running strace on: {}", command.join(" "));
    eprintln!("Trace output: {}", trace_path);
    
    // Run strace
    let status = Command::new("strace")
        .arg("-o")
        .arg(&trace_path)
        .arg("-t")  // timestamps
        .arg("-k")  // backtraces
        .arg("-f")  // follow forks
        .arg("-s")
        .arg("1024")  // string capture size
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
    
    eprintln!("Parsing trace output...");
    
    // Parse the trace file
    parse_file(&trace_path, output, resolve, pretty);
    
    // Clean up trace file unless keep_trace is set
    if !keep_trace {
        if let Err(e) = std::fs::remove_file(&trace_path) {
            eprintln!("Warning: Failed to remove trace file: {}", e);
        } else {
            eprintln!("Cleaned up trace file");
        }
    } else {
        eprintln!("Trace file kept at: {}", trace_path);
    }
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
    let error_info: Vec<ParseErrorInfo> = errors.iter()
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
        total_duration: if total_duration > 0.0 { Some(total_duration) } else { None },
    }
}

