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
    discord_bot_status: bool,
    // C1 (design doc §2.4): config-degraded state. The daemon never reports
    // healthy while any config file is missing/malformed — the main menu
    // shows a yellow banner + a "Degraded" daemon row instead of green.
    daemon_degraded: bool,
    degraded_reason: String,
}

impl Default for MainMenuState {
    fn default() -> Self {
        Self {
            ipc_status: false,
            daemon_status: false,
            firewall_status: false,
            discord_bot_status: false,
            daemon_degraded: false,
            degraded_reason: String::new(),
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
    /// C1: `Some(reason)` => degraded banner + "Degraded" daemon row;
    /// `None` => cleared (healthy).
    pub fn set_degraded(&mut self, reason: Option<String>) {
        match reason {
            Some(r) => {
                self.daemon_degraded = true;
                self.degraded_reason = r;
            }
            None => {
                self.daemon_degraded = false;
                self.degraded_reason = String::new();
            }
        }
    }
    pub fn reset_status_values(&mut self) {
        self.ipc_status = false;
        self.daemon_status = false;
        self.firewall_status = false;
        self.discord_bot_status = false;
        self.daemon_degraded = false;
        self.degraded_reason = String::new();
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

    // C1 (design doc §2.4): degraded-config banner (yellow) when the daemon
    // reports a missing/malformed config file — "safe but not as intended"
    // must be visible without hunting through logs.
    let (banner_area, rows_area) = if app.main_menu.daemon_degraded {
        let l = Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).split(inner_area);
        (Some(l[0]), l[1])
    } else {
        (None, inner_area)
    };
    if let Some(ba) = banner_area {
        let banner_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow));
        let ba_inner = banner_block.inner(ba);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!("⚠ CONFIG DEGRADED: {}", app.main_menu.degraded_reason),
                Style::default().fg(Color::Yellow),
            )))
            .wrap(Wrap { trim: true }),
            ba_inner,
        );
        f.render_widget(banner_block, ba);
    }

    // Create a vertical layout for each status row
    let rows_layout = Layout::vertical([
        Constraint::Length(3), // Firewall
        Constraint::Length(3), // IPC
        Constraint::Length(3), // Daemon
        Constraint::Length(3), // Discord Bot
        Constraint::Min(0),    // Spacer
    ]).split(rows_area);

    // Define the statuses and their styles (name, active, degraded, color)
    let statuses = [
        ("Firewall:", app.main_menu.firewall_status, false, Color::Rgb(255, 165, 0)),
        ("IPC:", app.main_menu.ipc_status, false, Color::Magenta),
        ("Daemon:", app.main_menu.daemon_status, app.main_menu.daemon_degraded, Color::Cyan),
        ("Discord Bot:", app.main_menu.discord_bot_status, false, Color::Blue),
    ];

    // Render each status row
    for (i, (name, is_active, is_degraded, color)) in statuses.iter().enumerate() {
        let row_area = rows_layout[i];

        // Create a centered area that is 50% of the row's width
        let centered_row_area = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Percentage(50),
            Constraint::Percentage(25),
        ]).split(row_area)[1];

        // Determine styles based on active/degraded status
        let (status_text, status_style, border_style) = if *is_degraded {
            // C1: the component is up but not fully healthy — yellow, not green
            ("Degraded", Style::default().fg(Color::Yellow), Style::default().fg(Color::Yellow))
        } else if *is_active {
            // If active: status text is green, border is the component's color
            ("Active", Style::default().fg(Color::Green), Style::default().fg(*color))
        } else {
            // If inactive: status text is red, border is red
            ("Inactive", Style::default().fg(Color::Red), Style::default().fg(Color::Red))
        };

        // Create a single block for the whole row, with border color reflecting status
        let combined_block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style);

        // Get the inner area of the block to create a new layout inside it
        let inner_block_area = combined_block.inner(centered_row_area);

        // Split the inner area to align the component name and status separately
        let inner_chunks = Layout::horizontal([
            Constraint::Percentage(50), // Left side for component name
            Constraint::Percentage(50), // Right side for status
        ]).split(inner_block_area);

        // Component name paragraph (right-aligned)
        let component_paragraph = Paragraph::new(Span::styled(*name, Style::default().fg(*color)))
            .right_aligned();

        // Status paragraph (left-aligned)
        let status_paragraph = Paragraph::new(Span::styled(format!(" {}", status_text), status_style))
            .left_aligned();

        // Render the block first, then the content inside its chunks
        f.render_widget(combined_block, centered_row_area);
        f.render_widget(component_paragraph, inner_chunks[0]);
        f.render_widget(status_paragraph, inner_chunks[1]);
    }

    f.render_widget(status_box_block, main_vertical_content_layout[0]); // Render the block after its inner area is used
}
