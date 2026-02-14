mod parser;

use clap::Parser as ClapParser;
use parser::{Addr2LineResolver, StraceParser, StraceOutput, SummaryStats, ParseErrorInfo};
use std::collections::HashSet;

#[derive(ClapParser)]
#[command(name = "strace-tui")]
#[command(about = "Parse strace output and convert to structured data", long_about = None)]
struct Cli {
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
}

fn main() {
    let cli = Cli::parse();
    
    // Parse the strace output
    let mut parser = StraceParser::new();
    let mut entries = match parser.parse_file(&cli.input) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("Error parsing file: {}", err);
            std::process::exit(1);
        }
    };
    
    // Resolve backtraces if requested
    if cli.resolve {
        eprintln!("Resolving backtraces with addr2line...");
        let mut resolver = Addr2LineResolver::new();
        
        for entry in entries.iter_mut() {
            if !entry.backtrace.is_empty() {
                let _ = resolver.resolve_frames(&mut entry.backtrace);
            }
        }
        
        eprintln!("Resolved {} unique addresses", resolver.cache_size());
    }
    
    // Generate summary stats
    let summary = generate_summary(&entries);
    
    // Convert parse errors
    let error_info: Vec<ParseErrorInfo> = parser.errors.iter()
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
    let json = if cli.pretty {
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
    if let Some(output_file) = cli.output {
        if let Err(err) = std::fs::write(&output_file, json) {
            eprintln!("Error writing to {}: {}", output_file, err);
            std::process::exit(1);
        }
        eprintln!("Output written to {}", output_file);
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

