mod app;
mod ui;
mod events;
mod syscall_colors;
mod process_graph;

pub use app::App;
use events::EventHandler;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use std::io;

pub fn run_tui(
    entries: Vec<crate::parser::SyscallEntry>,
    summary: crate::parser::SummaryStats,
    file_path: Option<String>,
) -> io::Result<()> {
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
