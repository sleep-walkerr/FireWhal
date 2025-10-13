/*
Add usage bars showing how much traffic is flowing for IPv4 and IPv6
Show basic status of each subapp, for now each will show inactive


*/
use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;


/// Holds the state for the Main Menu screen.
#[derive(Debug)]
pub struct MainMenuState {
    pub progress: f64,
    pub progress_direction: i8,
    pub last_tick: std::time::Instant,
    ipc_status: bool,
    daemon_status: bool,
    firewall_status: bool,
    discord_bot_status: bool
}

impl Default for MainMenuState {
    fn default() -> Self {
        Self {
            progress: 0.0,
            progress_direction: 1,
            last_tick: std::time::Instant::now(),
            ipc_status: false,
            daemon_status: false,
            firewall_status: false,
            discord_bot_status: false
        }
    }
}

impl MainMenuState {
    pub fn update_progress(&mut self) {
        self.progress += (self.progress_direction as f64) * 0.01; // Adjust speed as needed

        // make this random later
        if self.progress >= 1.0 {
            self.progress = 1.0;
            self.progress_direction = -1; // Reverse direction
        } else if self.progress <= 0.0 {
            self.progress = 0.0;
            self.progress_direction = 1; // Reverse direction
        }
        self.last_tick = std::time::Instant::now();
    }
    pub fn set_ipc_status(&mut self, status: bool) {
        self.ipc_status = status;
    }
    pub fn set_daemon_status(&mut self, status: bool) {
        self.daemon_status = status;
    }
    pub fn set_firewall_status(&mut self, status: bool) {
        self.firewall_status = status;
    }
    pub fn set_discord_bot_status(&mut self, status: bool) {
        self.discord_bot_status = status
    }
}



pub fn render(f: &mut Frame, app: &mut App) {
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

    // --- CONTENT ---

    //Create a vertical (maybe horizontal too) alignment layout 
    let main_vertical_content_layout = Layout::vertical([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ]).split(chunks[1]);

    // --- STATUS PANEL (CENTERED) ---
    let status_box_block = Block::default()
        .title("System Status")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    
    let inner_area = status_box_block.inner(main_vertical_content_layout[0]);

    f.render_widget(status_box_block, main_vertical_content_layout[0]);

    let active_style = Style::default().fg(Color::Black).bg(Color::Green);

    // Changes

    // Capture area being used and split it in half
    let system_status_area = Layout::horizontal(
        [
        Constraint::Percentage(50),
        Constraint::Percentage(50),
        Constraint::Min(0)
        ]
    ).split(inner_area);

        let component_text = vec![
        Line::from(vec![
            Span::styled("Firewall:", Style::default().fg(Color::Rgb(255, 165, 0))),
            Span::raw(" "),
        ]).right_aligned(),
        Line::from(vec![
            Span::styled("IPC:", Style::default().fg(Color::Magenta)),
            Span::raw(" "),
        ]).right_aligned(),
        Line::from(vec![
            Span::styled("Daemon:", Style::default().fg(Color::Cyan)),
        ]).right_aligned(),
        Line::from(vec![
            Span::styled("Discord Bot:", Style::default().fg(Color::Blue)),
        ]).right_aligned(),
        ];

    let status_text = vec![
        Line::from(vec![
            if app.main_menu.firewall_status {Span::styled("Active", active_style)} else {Span::styled("Inactive", Style::default().fg(Color::Red))} 
        ]).left_aligned(),
        Line::from(vec![
            if app.main_menu.ipc_status {Span::styled("Active", active_style)} else {Span::styled("Inactive", Style::default().fg(Color::Red))}
        ]).left_aligned(),
        Line::from(vec![
            if app.main_menu.daemon_status {Span::styled("Active", active_style)} else {Span::styled("Inactive", Style::default().fg(Color::Red))}
        ]).left_aligned(),
        Line::from(vec![
            if app.main_menu.discord_bot_status {Span::styled("Active", active_style)} else {Span::styled("Inactive", Style::default().fg(Color::Red))}
        ]).left_aligned(),
    ];

    let component_paragraph = Paragraph::new(component_text);
    let status_paragraph = Paragraph::new(status_text);

    f.render_widget(component_paragraph, system_status_area[0]);
    f.render_widget(status_paragraph, system_status_area[1]);


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
        .percent((app.main_menu.progress * 100.0) as u16) // Use progress from MainMenuState
        .label(format!("{:.0}%", app.main_menu.progress * 100.0)); // Display percentage

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