// import UI screens
mod ui;
use ui::app;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, SetTitle},
};

use ratatui::{prelude::*, widgets::*, Terminal};
use std::{
    error::Error,
    io::{self,stdout},
    ops::{self, RangeBounds, RangeTo},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use tokio::{
    task::spawn_blocking,
    time::sleep,
    sync::{broadcast, mpsc},
};
use zmq;
use firewhal_core::{zmq_client_connection, FireWhalMessage, StatusUpdate};
use tokio::sync::mpsc::error::TryRecvError;

/// Holds the application's state
struct App<> {
    titles: Vec<String>,
    index: usize,
    progress: f64, // New: Current progress for the gauge (0.0 to 1.0)
    progress_direction: i8, // New: 1 for increasing, -1 for decreasing
    last_tick: Instant, // New: To control animation speed
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Connect to IPC
    // `to_zmq_tx` is for the TUI to send messages TO the ZMQ task.
    // `from_zmq_rx` is for the TUI to receive messages FROM the ZMQ task.
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);

    // Spawn the ZMQ task.
    // `to_zmq_rx` is the `outgoing_rx` for the ZMQ task.
    // `from_zmq_tx` is the `incoming_tx` for the ZMQ task.
    let ipc_connection = tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx));

    let ident_message = FireWhalMessage::Status(StatusUpdate {
        component: "TUI".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    }
    );
    
    // Unhandled error, needs to be fixed later
    _ = to_zmq_tx.send(ident_message).await;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide, SetTitle("FireWhal 🔥🐳"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?; // ⬅ clear screen before drawing

    let mut app = app::App::default();
    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| ui::render(f, &app))?;

        let timeout = tick_rate
            .checked_sub(app.last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Tab => app.next_screen(),
                    _ => {}
                }
            }
        }
        if app.last_tick.elapsed() >= tick_rate {
            app.update_progress();
            app.last_tick = Instant::now();
        }

        // Process all pending messages from the ZMQ task.
        loop {
            match from_zmq_rx.try_recv() {
                Ok(FireWhalMessage::Debug(msg)) => {
                    // Add the formatted message to the app's state.
                    let formatted_msg = format!("[{}]: {}", msg.source, msg.content);
                    app.debug_messages.push(formatted_msg);
                }
                Ok(_) => { /* Ignore other message types for now */ }
                Err(TryRecvError::Empty) => {
                    // No more messages in the queue.
                    break;
                }
                Err(TryRecvError::Disconnected) => {
                    // The ZMQ task has shut down, so we should exit.
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, crossterm::cursor::Show)?;
    terminal.show_cursor()?; // optional: make sure cursor reappears

    // 3. Send the shutdown signal
    println!("TUI exited. Shutting down ZMQ task...");
    drop(to_zmq_tx); // This will cause the zmq_client_connection to exit its loop.

    // 4. Wait for the ZMQ task to finish cleanly
    if let Err(e) = ipc_connection.await {
        eprintln!("ZMQ task did not shut down cleanly: {:?}", e);
    }

    Ok(())
}