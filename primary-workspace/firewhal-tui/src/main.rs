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

/// Holds the application's state
struct App<> {
    titles: Vec<String>,
    index: usize,
    progress: f64, // New: Current progress for the gauge (0.0 to 1.0)
    progress_direction: i8, // New: 1 for increasing, -1 for decreasing
    last_tick: Instant, // New: To control animation speed
}

async fn ipc_connection(
    _msg: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    msg_tx: mpsc::Sender<String>,
) {
    // This flag will be shared between our async task and the blocking ZMQ thread.
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // The actual blocking ZMQ work is offloaded to a blocking thread.
    let mut blocking_task = spawn_blocking(move || -> Result<(), zmq::Error> {
        let context = zmq::Context::new();
        let dealer = context.socket(zmq::DEALER).unwrap();
        // Set a timeout on receive so the loop doesn't block forever.
        dealer.set_rcvtimeo(500)?;
        // Set linger to 0 to prevent blocking on close.
        dealer.set_linger(0)?;
        assert!(dealer.connect("ipc:///tmp/firewhal_ipc.sock").is_ok());

        dealer.send("TUI_READY", 0)?;

        // Loop until the shutdown flag is set.
        while running_clone.load(Ordering::Relaxed) {
            let mut msg = zmq::Message::new();
            match dealer.recv(&mut msg, 0) {
                Ok(_) => {
                    let msg_str = msg.as_str().unwrap_or("");
                    // Send the received message to the main UI thread.
                    // We use `blocking_send` because we are in a thread spawned by `spawn_blocking`.
                    if msg_tx.blocking_send(msg_str.to_string()).is_err() {
                        break; // Stop if the receiver has been dropped (UI closed).
                    }

                    if msg_str == "Hash has changed" {
                        let _ = dealer.send("Hash changed notification received by TUI ZMQ", 0);
                    }
                }
                Err(zmq::Error::EAGAIN) => {
                    // Timeout hit, this is expected. Loop again to check the `running` flag.
                    continue;
                }
                Err(e) => {
                    // A real error occurred.
                    eprintln!("ZMQ recv error: {}", e);
                    break;
                }
            }
        }
        Ok(())
    });

    // This is our async control loop.
    tokio::select! {
        // Wait for the shutdown signal
        _ = shutdown_rx.recv() => {
            println!("Shutdown signal received in ZMQ task. Stopping blocking thread.");
            running.store(false, Ordering::Relaxed);
        },
        // Or wait for the blocking task to finish on its own
        _ = &mut blocking_task => {
            println!("ZMQ blocking task finished before shutdown signal.");
        }
    };

    // After signaling shutdown, we must wait for the blocking task to actually finish.
    if let Err(e) = blocking_task.await {
        eprintln!("ZMQ blocking task panicked or was cancelled: {}", e);
    } else {
        println!("ZMQ task shut down gracefully.");
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Connect to IPC
    // 1. Setup graceful shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    // New: Setup channel for IPC messages to UI
    let (msg_tx, mut msg_rx) = mpsc::channel(100);

    // 2. Spawn the ZMQ task, giving it a way to listen for the shutdown signal
    let message_sender_handle = tokio::spawn(ipc_connection(
        "TUI_READY".to_string(),
        shutdown_rx,
        msg_tx,
    ));
        
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

        // Check for IPC messages from the ZMQ task without blocking the UI.
        if let Ok(msg) = msg_rx.try_recv() {
            app.add_debug_message(msg);
        }

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
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, crossterm::cursor::Show)?;
    terminal.show_cursor()?; // optional: make sure cursor reappears

    // 3. Send the shutdown signal
    println!("TUI exited. Sending shutdown signal to ZMQ task...");
    let _ = shutdown_tx.send(());

    // 4. Wait for the ZMQ task to finish cleanly
    if let Err(e) = message_sender_handle.await {
        eprintln!("ZMQ task did not shut down cleanly: {:?}", e);
    }

    Ok(())
}