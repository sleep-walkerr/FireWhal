// import UI screens
mod ui;
use ui::app::{App, AppScreen};
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

// Upon entering the interface selection menu, have the TUI send a message requesting the interface list
// The userspace loader receives the message, scans for interfaces, and then sends a request response
// The TUI then populates the list with the message it receives containing the available interfaces


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

    let mut app = App::default();
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Tab => {
                        app.next_screen();
                        // THIS CODE CAUSES BUSY WAITING
                        // Match to correct interface and then perform relevant operations
                        match app.screen {
                            AppScreen::InterfaceSelection => {
                                // Send a interface request message to firewhal-kernel if screen is interface selection
                                // Craft request message
                                let request_message = FireWhalMessage::InterfaceRequest(firewhal_core::NetInterfaceRequest {
                                    source: "TUI".to_string(),
                                });
                                // Send request message
                                if let Err(e) = to_zmq_tx.send(request_message).await {
                                    eprintln!("Failed to send interface request: {}", e);
                                }
                            },
                            // AppScreen::MainMenu => {
                            //     if last_tick.elapsed() >= tick_rate {
                            //         app.main_menu.update_progress();
                            //         last_tick = Instant::now();
                            //     }
                                
                            // },
                            _ => {}
                        }
                    },
                    _ => {}
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            // Delegate updates to the active screen's state
            match app.screen {
                AppScreen::MainMenu => app.main_menu.update_progress(),
                _ => { /* Other screens might have their own updates here */ }
            }
            last_tick = Instant::now();
        }


        


        // Process all pending messages from the ZMQ task.
        loop {
            match from_zmq_rx.try_recv() {
                Ok(FireWhalMessage::Debug(msg)) => {
                    // Add the formatted message to the app's state.
                    let formatted_msg = format!("[{}]: {}", msg.source, msg.content);
                    app.debug_print.add_message(formatted_msg);
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