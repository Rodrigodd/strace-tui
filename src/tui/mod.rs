mod app;
mod process_graph;
mod syscall_colors;
mod ui;

pub use app::App;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::time::Duration;

pub fn run_tui(
    entries: Vec<crate::parser::SyscallEntry>,
    summary: crate::parser::SummaryStats,
    file_path: Option<String>,
) -> io::Result<()> {
    // Initialize logging to file only if RUST_LOG is set
    if std::env::var("RUST_LOG").is_ok() {
        // Get the cache directory (or state directory on Linux)
        let log_dir = dirs::cache_dir()
            .or_else(dirs::state_dir)
            .unwrap_or_else(std::env::temp_dir);

        let log_dir = log_dir.join("strace-tui");

        // Create the directory if it doesn't exist
        fs::create_dir_all(&log_dir).expect("Failed to create log directory");

        let log_path = log_dir.join("strace-tui.log");

        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("Failed to open log file");

        env_logger::Builder::new()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .parse_default_env()
            .init();

        log::info!("Starting strace-tui - log file: {}", log_path.display());
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new(entries, summary, file_path);

    // Run the main loop
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

fn run_app<B: ratatui::backend::Backend + io::Write>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> Result<(), B::Error>
where
    B::Error: From<std::io::Error>,
{
    loop {
        let app_ref = &mut *app;
        terminal.draw(move |f| ui::draw(f, app_ref))?;

        if let Some(event) = get_event()? {
            app.handle_event(event);
        }

        if app.should_quit {
            return Ok(());
        }

        // Check if we need to open an editor
        if let Some((file, line, column)) = app.pending_editor_open.take() {
            // Suspend the TUI - proper cleanup
            disable_raw_mode()?;
            execute!(
                terminal.backend_mut(),
                LeaveAlternateScreen,
                DisableMouseCapture
            )?;
            terminal.show_cursor()?;

            // Flush the terminal to ensure all commands are executed
            io::stdout().flush()?;

            // Open the editor (blocking)
            if let Err(e) = open_editor_foreground(&file, line, column) {
                eprintln!("Error opening editor: {}", e);
                // Wait for user to press Enter before continuing
                eprintln!("Press Enter to continue...");
                let mut input = String::new();
                io::stdin().read_line(&mut input).ok();
            }

            // Resume the TUI
            enable_raw_mode()?;
            execute!(
                terminal.backend_mut(),
                EnterAlternateScreen,
                EnableMouseCapture
            )?;
            terminal.hide_cursor()?;

            // Force a full redraw
            terminal.clear()?;
        }
    }
}

pub fn get_event() -> io::Result<Option<KeyEvent>> {
    if event::poll(Duration::from_millis(100))?
        && let Event::Key(key) = event::read()?
    {
        // Only process key press events, not release
        if key.kind == KeyEventKind::Press {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Open editor in foreground (blocking)
fn open_editor_foreground(file: &str, line: u32, column: Option<u32>) -> Result<(), String> {
    use std::env;
    use std::process::Command;

    // Get editor from environment
    let editor_env = env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());

    // Parse editor command (may have multiple parts like "code --wait")
    let parts: Vec<&str> = editor_env.split_whitespace().collect();
    if parts.is_empty() {
        return Err("EDITOR is empty".to_string());
    }

    let editor_cmd = parts[0];
    let editor_args: Vec<&str> = parts[1..].to_vec();

    // Detect editor and build appropriate command
    let editor_name = std::path::Path::new(editor_cmd)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(editor_cmd);

    let mut cmd = Command::new(editor_cmd);

    // Add any existing args from EDITOR
    for arg in editor_args {
        cmd.arg(arg);
    }

    // Add editor-specific line/column arguments
    match editor_name {
        "vim" | "vi" | "nvim" | "neovim" => {
            // vim/nvim: +{line} or +call cursor({line},{col})
            if let Some(col) = column {
                cmd.arg(format!("+call cursor({},{})", line, col));
            } else {
                cmd.arg(format!("+{}", line));
            }
            cmd.arg(file);
        }
        "nano" => {
            // nano: +{line},{col} file
            if let Some(col) = column {
                cmd.arg(format!("+{},{}", line, col));
            } else {
                cmd.arg(format!("+{}", line));
            }
            cmd.arg(file);
        }
        "emacs" | "emacsclient" => {
            // emacs: +{line}:{col} file
            if let Some(col) = column {
                cmd.arg(format!("+{}:{}", line, col));
            } else {
                cmd.arg(format!("+{}", line));
            }
            cmd.arg(file);
        }
        "code" | "vscode" | "code-insiders" => {
            // vscode: --goto file:line:col (add --wait to make it blocking)
            cmd.arg("--wait");
            if let Some(col) = column {
                cmd.arg("--goto").arg(format!("{}:{}:{}", file, line, col));
            } else {
                cmd.arg("--goto").arg(format!("{}:{}", file, line));
            }
        }
        "subl" | "sublime" | "sublime_text" => {
            // sublime: file:line:col (add --wait to make it blocking)
            cmd.arg("--wait");
            if let Some(col) = column {
                cmd.arg(format!("{}:{}:{}", file, line, col));
            } else {
                cmd.arg(format!("{}:{}", file, line));
            }
        }
        "kate" => {
            // kate: -l {line} -c {col} file
            cmd.arg("-l").arg(line.to_string());
            if let Some(col) = column {
                cmd.arg("-c").arg(col.to_string());
            }
            cmd.arg(file);
        }
        "gedit" | "gnome-text-editor" => {
            // gedit: +{line}:{col} file
            if let Some(col) = column {
                cmd.arg(format!("+{}:{}", line, col));
            } else {
                cmd.arg(format!("+{}", line));
            }
            cmd.arg(file);
        }
        "micro" => {
            // micro: file:{line}:{col}
            if let Some(col) = column {
                cmd.arg(format!("{}:{}:{}", file, line, col));
            } else {
                cmd.arg(format!("{}:{}", file, line));
            }
        }
        "helix" | "hx" => {
            // helix: file:{line}:{col}
            if let Some(col) = column {
                cmd.arg(format!("{}:{}:{}", file, line, col));
            } else {
                cmd.arg(format!("{}:{}", file, line));
            }
        }
        _ => {
            // Unknown editor, try vim-style as fallback
            if let Some(col) = column {
                cmd.arg(format!("+call cursor({},{})", line, col));
            } else {
                cmd.arg(format!("+{}", line));
            }
            cmd.arg(file);
        }
    }

    log::debug!("Opening editor: {:?}", cmd);

    // Ensure the editor inherits stdin/stdout/stderr from the parent process
    // This is crucial for TUI editors (nano, vim, etc.) to work properly
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    // Run the editor in foreground (blocking) - wait for it to finish
    let status = cmd
        .status()
        .map_err(|e| format!("Failed to run editor: {}", e))?;

    if !status.success() {
        return Err(format!("Editor exited with status: {}", status));
    }

    Ok(())
}
