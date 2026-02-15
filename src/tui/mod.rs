mod app;
mod events;
mod process_graph;
mod syscall_colors;
mod ui;

pub use app::App;
use events::EventHandler;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::fs::{self, OpenOptions};
use std::io;

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
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

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
    let mut event_handler = EventHandler::new();

    // Run the main loop
    let res = run_app(&mut terminal, &mut app, &mut event_handler);

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

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    event_handler: &mut EventHandler,
) -> io::Result<()> {
    loop {
        let app_ref = &mut *app;
        terminal.draw(move |f| ui::draw(f, app_ref))?;

        if let Some(event) = event_handler.next()? {
            app.handle_event(event);
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
