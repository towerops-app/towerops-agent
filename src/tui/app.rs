use std::io::{self, Stdout};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::{broadcast, watch};
use tokio::time::interval;

use super::events::AgentEvent;
use super::state::AgentState;
use super::ui;

pub struct TuiApp {
    state: Arc<Mutex<AgentState>>,
    event_rx: broadcast::Receiver<AgentEvent>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    scroll_offset: usize,
}

impl TuiApp {
    pub fn new(
        state: Arc<Mutex<AgentState>>,
        event_rx: broadcast::Receiver<AgentEvent>,
    ) -> anyhow::Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            state,
            event_rx,
            terminal,
            scroll_offset: 0,
        })
    }

    pub async fn run(&mut self, mut shutdown_rx: watch::Receiver<bool>) -> anyhow::Result<()> {
        let mut tick_interval = interval(Duration::from_millis(100)); // 10 FPS

        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = shutdown_rx.changed() => {
                    break;
                }

                // Handle agent events
                result = self.event_rx.recv() => {
                    match result {
                        Ok(event) => {
                            let mut state = self.state.lock().unwrap();
                            state.apply_event(&event);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            tracing::warn!("TUI lagged behind, skipped {} events", skipped);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }

                // Render tick
                _ = tick_interval.tick() => {
                    self.render()?;
                }

                // Handle keyboard input (non-blocking)
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if event::poll(Duration::from_millis(0))? {
                        if let Event::Key(key) = event::read()? {
                            if self.handle_key(key) {
                                break; // User pressed 'q' to quit
                            }
                        }
                    }
                }
            }
        }

        self.cleanup()?;
        Ok(())
    }

    fn render(&mut self) -> anyhow::Result<()> {
        let state = self.state.lock().unwrap().clone();
        let scroll_offset = self.scroll_offset;

        self.terminal.draw(|f| {
            ui::render(f, &state, scroll_offset);
        })?;

        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => {
                return true; // Signal to quit
            }
            KeyCode::Up => {
                self.scroll_offset = self.scroll_offset.saturating_add(1);
            }
            KeyCode::Down => {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
            KeyCode::PageUp => {
                self.scroll_offset = self.scroll_offset.saturating_add(10);
            }
            KeyCode::PageDown => {
                self.scroll_offset = self.scroll_offset.saturating_sub(10);
            }
            KeyCode::Home => {
                // Go to end (most recent events)
                self.scroll_offset = 0;
            }
            KeyCode::End => {
                // Go to beginning (oldest events)
                let state = self.state.lock().unwrap();
                self.scroll_offset = state.recent_events.len().saturating_sub(1);
            }
            _ => {}
        }
        false
    }

    fn cleanup(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen,)?;
        self.terminal.show_cursor()?;
        Ok(())
    }
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        // Ensure terminal is restored even on panic
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen,);
        let _ = self.terminal.show_cursor();
    }
}
