use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{prelude::*, widgets::*};
use std::{
    error::Error,
    io,
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
    sync::broadcast
};
use zmq;

/// Holds the application's state
struct App<'a> {
    titles: Vec<&'a str>,
    index: usize,
    progress: f64, // New: Current progress for the gauge (0.0 to 1.0)
    progress_direction: i8, // New: 1 for increasing, -1 for decreasing
    last_tick: Instant, // New: To control animation speed
}

impl<'a> App<'a> {
    fn new() -> App<'a> {
        App {
            titles: vec!["Status", "Rule Management", "Notifications", "Active Connections"],
            index: 0,
            progress: 0.0,
            progress_direction: 1,
            last_tick: Instant::now(),
        }
    }

    /// Moves to the next tab, wrapping around if necessary.
    pub fn next(&mut self) {
        self.index = (self.index + 1) % self.titles.len();
    }

    /// Updates the gauge progress for animation
    pub fn update_progress(&mut self) {
        self.progress += (self.progress_direction as f64) * 0.01; // Adjust speed as needed

        // make this random later
        if self.progress >= 1.0 {
            self.progress = 1.0;
            self.progress_direction = -1;
        } else if self.progress <= 0.0 {
            self.progress = 0.0;
            self.progress_direction = 1;
        }
    }
}

async fn nonblocking_zmq_message_sender(
    _msg: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
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
                    // Note: `println!` will mess up the TUI display.
                    // For debugging, it's better to log to a file.
                    // e.g., log::info!("TUI received message: '{}'", msg_str);
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
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Setup graceful shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

    // 2. Spawn the ZMQ task, giving it a way to listen for the shutdown signal
    let message_sender_handle =
        tokio::spawn(nonblocking_zmq_message_sender("TUI_READY".to_string(), shutdown_rx));

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let mut app = App::new();
    let tick_rate = Duration::from_millis(100); // Animation update rate
    let res = run_app(&mut terminal, app, tick_rate);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    // 3. Send the shutdown signal
    println!("TUI exited. Sending shutdown signal to ZMQ task...");
    let _ = shutdown_tx.send(());

    // 4. Wait for the ZMQ task to finish cleanly
    if let Err(e) = message_sender_handle.await {
        eprintln!("ZMQ task did not shut down cleanly: {:?}", e);
    }

    Ok(())
}

/// The main application loop.
fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App, tick_rate: Duration) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &app))?;

        let timeout = tick_rate
            .checked_sub(app.last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Tab => app.next(),
                    _ => {}
                }
            }
        }
        if app.last_tick.elapsed() >= tick_rate {
            app.update_progress();
            app.last_tick = Instant::now();
        }
    }
}

/// The main rendering function.
fn ui(f: &mut Frame, app: &App) {
    // --- TITLE ---
    let firewhal_span = Span::styled(
        "FireWhal ",
        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
    );
    let icon_span = Span::styled(
        "",
        Style::default().fg(Color::Rgb(255, 165, 0)), // Orange
    );
    let title = Line::from(vec![firewhal_span, icon_span]);

    let main_block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center)
        .border_type(BorderType::Rounded);

    let main_inner_area = main_block.inner(f.area());
    f.render_widget(main_block, f.area());

    // --- LAYOUT ---
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .split(main_inner_area);

    // --- TABS ---
    let tab_titles: Vec<Span<'_>> = app
        .titles
        .iter()
        .map(|t| Span::styled(*t, Style::default().fg(Color::Blue)))
        .collect();

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().title("Navigation").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED)
                .underline_color(Color::Rgb(255, 165, 0)),
        )
        .select(app.index);

    f.render_widget(tabs, chunks[0]);

    // --- CONTENT ---
    let status_title = Span::raw("Firewall Status: ");
    let status_state = Span::styled(
        "Active",
        Style::default().fg(Color::Black).bg(Color::Green),
    );
    let content_title = Line::from(vec![status_title, status_state]);

    let content_block = Block::default()
        .title(content_title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let content_inner_area = content_block.inner(chunks[1]);
    f.render_widget(content_block, chunks[1]);


    // // --- INNER CONTENT LAYOUT (FOR CENTERING) ---

    // // 1. Define the fixed size of the status box.
    // const STATUS_BOX_WIDTH: u16 = 25;
    // const STATUS_BOX_HEIGHT: u16 = 5; // 3 lines of text + 2 for top/bottom borders

    // // 2. Define the fixed size of the usage bar.
    // const GAUGE_WIDTH: u16 = 40;
    // const GAUGE_HEIGHT: u16 = 3; // 1 line for gauge + 2 for top/bottom borders

    // // Calculate areas for both widgets
    // let status_box_area = centered_rect(content_inner_area, STATUS_BOX_WIDTH, STATUS_BOX_HEIGHT, 0.3); // 30% from top
    // let gauge_area = centered_rect(content_inner_area, GAUGE_WIDTH, GAUGE_HEIGHT, 0.6); // 60% from top

    //Create a vertical (maybe horizontal too) alignment layout 
    let main_vertical_content_layout = Layout::vertical([
        Constraint::Length(25),
        Constraint::Length(30),
        Constraint::Min(0)
    ]).split(chunks[1]);

    // --- STATUS PANEL (CENTERED) ---
    let status_box_block = Block::default()
        .title("System Status")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));

    let active_style = Style::default().fg(Color::Black).bg(Color::Green);
    let status_text = vec![
        Line::from(vec![
            Span::raw("Daemon:   "),
            Span::styled("Active", active_style),
        ]),
        Line::from(vec![
            Span::raw("Notifier: "),
            Span::styled("Active", active_style),
        ]),
        Line::from(vec![
            Span::raw("eBPF:     "),
            Span::styled("Active", active_style),
        ]),
    ];

    let status_paragraph = Paragraph::new(status_text)
        .block(status_box_block)
        .alignment(Alignment::Center);

    f.render_widget(status_paragraph, main_vertical_content_layout[0]);


    //Network Usage One time Position Calculation
    // This will need a helper function that is called any time the window is resized or moved
    //This is manual centering, there may be a way to do all of this automatically
    //clamp function automatically fits a rectangle within another
    // Using fractional scaling as much as possible
    let network_usage_position = {
        let parent_rect = main_vertical_content_layout[1];
        let width = parent_rect.width / 2;
        let height = 3;
        let x = (parent_rect.width / 2) - width / 2;
        let y = (parent_rect.height / 2) - height / 2;
        Rect::new(
        x,
        y, 
        width, 
        height)
    };
    // println!("Area testing: {}", f.area().);

    // --- NETWORK USAGE BAR (CENTERED BELOW STATUS) ---
    let network_usage_bar = Gauge::default()
        .block(Block::default().title("Network Usage").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
        .percent((app.progress * 100.0) as u16) // Use app.progress
        .label(format!("{:.0}%", app.progress * 100.0)); // Display percentage

    f.render_widget(network_usage_bar,main_vertical_content_layout[1])
}

/// Helper function to create a centered rect of a fixed size at a specific vertical position.
/// `r` is the full area, `width` and `height` are for the box, `v_offset_percent` is
/// how far down the box should start from the top of `r` (0.0 to 1.0).
fn centered_rect(r: Rect, width: u16, height: u16, v_offset_percent: f32) -> Rect {
    let popup_layout_vertical = Layout::vertical([
        Constraint::Percentage((v_offset_percent * 100.0) as u16), // Top offset
        Constraint::Length(height), // Fixed height for the widget
        Constraint::Min(0), // Remaining space
    ])
    .split(r);

    let popup_layout_horizontal = Layout::horizontal([
        Constraint::Percentage((100 - width) / 2),
        Constraint::Length(width),
        Constraint::Percentage((100 - width) / 2),
    ])
    .split(popup_layout_vertical[1]); // Use the middle chunk from vertical layout

    popup_layout_horizontal[1]
}