use crossterm::event::{self, Event, KeyEvent, KeyEventKind};
use std::io;
use std::time::Duration;

pub struct EventHandler;

impl EventHandler {
    pub fn new() -> Self {
        Self
    }

    pub fn next(&mut self) -> io::Result<Option<KeyEvent>> {
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
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}
