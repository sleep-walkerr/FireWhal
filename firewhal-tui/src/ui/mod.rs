use ratatui::{prelude::*, widgets::*};

use self::app::{App, AppScreen};

pub mod app;
pub mod app_management;
pub mod debug_print;
pub mod interface_selection;
pub mod main_menu;
pub mod permissive_mode;
pub mod rule_management;

/// The top-level render function that orchestrates the UI layout.
pub fn render(f: &mut Frame, app: &mut App) {
    // --- Overall Layout: Vertical Navigation (Left) + Content (Right) ---
    let main_layout = Layout::horizontal([
        Constraint::Length(25), // Fixed width for navigation pane
        Constraint::Min(0),     // Remaining space for content
    ])
    .split(f.size());

    let nav_area = main_layout[0];
    let content_area = main_layout[1];

    // --- Render Navigation Pane ---
    render_navigation_pane(f, app, nav_area);

    // --- Render Content Pane based on selected screen ---
    match app.screen {
        AppScreen::MainMenu => main_menu::render(f, app, content_area),
        AppScreen::InterfaceSelection => interface_selection::render(f, app, content_area),
        AppScreen::RuleManagement => rule_management::render(f, app, content_area),
        AppScreen::AppManagement => app_management::render(f, app, content_area),
        AppScreen::PermissiveMode => permissive_mode::render(f, app, content_area),
        AppScreen::Debug => {
            // The debug_print::render function now handles its own block
            debug_print::render(f, app, content_area);
        }
    }
}

fn render_navigation_pane(f: &mut Frame, app: &mut App, area: Rect) {
    let firewhal_span = Span::styled(
        "FireWhal ",
        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
    );
    let icon_span = Span::styled(
        "",
        Style::default().fg(Color::Rgb(255, 165, 0)), // Orange
    );
    let title = Line::from(vec![firewhal_span, icon_span]);

    let nav_block = Block::default()
        .title(title)
        .title_alignment(Alignment::Center)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if app.focus_on_navigation { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) });

    let inner_nav_area = nav_block.inner(area);
    f.render_widget(nav_block, area);

    let nav_items: Vec<ListItem> = app.nav_items.iter().map(|screen| {
        let text = format!("{:?}", screen);
        ListItem::new(text).style(Style::default().fg(Color::Blue))
    }).collect();

    let nav_list = List::new(nav_items)
        .highlight_style(
            Style::default()
                .fg(Color::Rgb(255, 165, 0)) // Orange
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::REVERSED),
        )
        .highlight_symbol(">> ");

    let mut list_state = ListState::default().with_selected(Some(app.nav_index));
    f.render_stateful_widget(nav_list, inner_nav_area, &mut list_state);
}

/// Helper to create a centered rect for popups
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ]).split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ]).split(popup_layout[1])[1]
}

/// Helper function to create a centered rect of a fixed size at a specific vertical position.
/// `r` is the full area, `width` and `height` are for the box, `v_offset_percent` is
/// how far down the box should start from the top of `r` (0.0 to 1.0).
pub fn centered_rect_with_v_offset(r: Rect, width: u16, height: u16, v_offset_percent: f32) -> Rect {
    let popup_layout_vertical = Layout::vertical([
        Constraint::Percentage((v_offset_percent * 100.0) as u16), // Top offset
        Constraint::Length(height), // Fixed height for the widget
        Constraint::Min(0), // Remaining space
    ]).split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - width) / 2),
        Constraint::Length(width),
        Constraint::Percentage((100 - width) / 2),
    ]).split(popup_layout_vertical[1])[1]
}
