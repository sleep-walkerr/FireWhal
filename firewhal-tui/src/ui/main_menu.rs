/*
Add usage bars showing how much traffic is flowing for IPv4 and IPv6
Show basic status of each subapp, for now each will show inactive


*/
use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;


/// Holds the state for the Main Menu screen.
#[derive(Debug)]
pub struct MainMenuState {
    ipc_status: bool,
    daemon_status: bool,
    firewall_status: bool,
    discord_bot_status: bool
}

impl Default for MainMenuState {
    fn default() -> Self {
        Self {
            ipc_status: false,
            daemon_status: false,
            firewall_status: false,
            discord_bot_status: false
        }
    }
}

impl MainMenuState {
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
    pub fn reset_status_values(&mut self) {
        self.ipc_status = false;
        self.daemon_status = false;
        self.firewall_status = false;
        self.discord_bot_status = false;
    }
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    // This function now only renders the content specific to the Main Menu screen

    // The main menu now only contains the status panel.
    let main_vertical_content_layout = Layout::vertical([Constraint::Percentage(100)]).split(area);

    // --- STATUS PANEL (CENTERED) ---
    let status_box_block = Block::default()
        .title("System Status")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue));
    
    let inner_area = status_box_block.inner(main_vertical_content_layout[0]); // Get inner area before rendering block

    let active_style = Style::default().fg(Color::Black).bg(Color::Green);

    // Changes

    // Capture area being used and split it in half
    let system_status_area = Layout::horizontal(
        [
        Constraint::Percentage(50),
        Constraint::Percentage(50), // Two 50% constraints are enough
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

    f.render_widget(status_box_block, main_vertical_content_layout[0]); // Render the block after its inner area is used
}
