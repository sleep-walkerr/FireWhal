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
        Constraint::Length(29), // Fixed width for navigation pane
        Constraint::Min(0),     // Remaining space for content
    ])
    .split(f.area());

    let nav_area = main_layout[0];
    let content_area = main_layout[1];

    // --- Render Navigation Pane ---
    render_navigation_pane(f, app, nav_area);

    // --- Render Content Pane based on selected screen ---
    match app.screen {
        AppScreen::MainMenu => {
            app.interface_list_state.select(None); // Clear selection when leaving
            main_menu::render(f, app, content_area)
        },
        AppScreen::InterfaceSelection => {
            // When entering the screen, if no item is selected, default to the first one.
            if app.interface_list_state.selected().is_none() && !app.available_interfaces.is_empty() {
                app.interface_list_state.select(Some(0));
            }
            interface_selection::render(f, app, content_area)
        },
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
        "FireWhal",
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
        .border_style(Style::default().fg(Color::Cyan));

    let inner_nav_area = nav_block.inner(area);
    f.render_widget(nav_block, area);

    let nav_items: Vec<ListItem> = app.nav_items.iter().enumerate().map(|(i, screen)| {
        let text = screen.display_name();
        if i == app.nav_index {
            // Create a full-width "tab" for the selected item
            let pane_width = inner_nav_area.width as usize;
            let bar_width = pane_width - 2;
            let top_border = format!("╭{}╮", "─".repeat(bar_width));
            let bottom_border = format!("╰{}╯", "─".repeat(bar_width));

            // Text is always orange
            let text_style = Style::default().fg(Color::Rgb(255, 165, 0));
            // Border color changes with focus
            let border_style = if app.focus_on_navigation {
                Style::default().fg(Color::Rgb(255, 165, 0)) // Orange when nav is focused
            } else {
                Style::default().fg(Color::DarkGray) // Gray when content is focused
            };

            // Create the middle line with separate styles for border and text
            let text_with_padding = format!(" {} ", text);
            let remaining_width = pane_width.saturating_sub(text_with_padding.len() + 2); // -2 for the │
            let middle_line = Line::from(vec![
                Span::styled("│", border_style),
                Span::styled(text_with_padding, text_style),
                Span::raw(" ".repeat(remaining_width)),
                Span::styled("│", border_style),
            ]);

            let lines = vec![
                Line::from(top_border).style(border_style),
                middle_line,
                Line::from(bottom_border).style(border_style),
            ];
            ListItem::new(lines).style(Style::default())
        } else {
            // Create a full-width "tab" for non-selected items, displaced to the right
            let right_shift = " "; // Displacement for non-selected items
            let pane_width = (inner_nav_area.width as usize).saturating_sub(right_shift.len());

            let border_style = Style::default().fg(Color::DarkGray);
            let text_style = Style::default().fg(Color::Blue);

            // --- Borders ---
            let bar_width = pane_width - 2;
            let top_border = format!("{}{}", right_shift, format!("╭{}╮", "─".repeat(bar_width)));
            let bottom_border = format!("{}{}", right_shift, format!("╰{}╯", "─".repeat(bar_width)));

            // --- Middle Line (with mixed styles) ---
            let text_with_padding = format!(" {} ", text);
            let remaining_width = pane_width.saturating_sub(text_with_padding.len() + 2); // -2 for the │
            let middle_line = Line::from(vec![
                Span::raw(right_shift),
                Span::styled("│", border_style),
                Span::styled(text_with_padding, text_style),
                Span::raw(" ".repeat(remaining_width)),
                Span::styled("│", border_style),
            ]);

            let lines = vec![
                Line::from(top_border).style(border_style),
                Line::from(middle_line).style(text_style),
                Line::from(bottom_border).style(border_style),
            ];
            ListItem::new(lines).style(Style::default())
        }
    }).collect();

    let nav_list = List::new(nav_items)
        .highlight_style(Style::default()); // Highlighting is now done manually

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
