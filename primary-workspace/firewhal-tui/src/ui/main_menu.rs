/*
Add usage bars showing how much traffic is flowing for IPv4 and IPv6
Show basic status of each subapp, for now each will show inactive


*/
use ratatui::{prelude::*, widgets::*};
use crate::app::App;


pub fn render(f: &mut Frame, app: &App) {
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

// pub fn render(f: &mut Frame) {
//     // 1. Create individual styled parts of the title
//     let firewhal_span = Span::styled(
//         "FireWhal ",
//         Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
//     );
//     let icon_span = Span::styled(
//         "",
//         Style::default().fg(Color::Rgb(255, 165, 0)), // A nice orange color
//     );

//     // 2. Combine the parts into a single `Line`
//     let title = Line::from(vec![firewhal_span, icon_span]);

//     // 3. Use the `Line` as the title for the main block
//     let main_block = Block::default()
//         .title(title) // The multi-colored title is now used here
//         .borders(Borders::ALL)
//         .title_alignment(Alignment::Center)
//         .border_type(BorderType::Rounded);

//     // Get the inner area from main_block *before* it's moved.
//     let main_inner_area = main_block.inner(f.area());
//     // Now, render the main_block.
//     f.render_widget(main_block, f.area());

//     // Create a layout to split the area inside the main block
//     let chunks = Layout::vertical([
//         Constraint::Length(3), // A fixed-height chunk for the tabs
//         Constraint::Min(0),    // The rest of the space for content
//     ])
//     .split(main_inner_area);

//     // Define the tab titles
//     let titles = vec!["Status", "Rule Management", "Notifications", "Active Connections"];
//     let tabs = Tabs::new(titles)
//         .block(Block::default().title("Navigation").borders(Borders::ALL))
//         .style(Style::default().fg(Color::White))
//         .highlight_style(
//             Style::default()
//                 .fg(Color::Yellow)
//                 .add_modifier(Modifier::BOLD),
//         )
//         .select(0);

//     // Render the tabs in the top chunk
//     f.render_widget(tabs, chunks[0]);

//     // Your existing content block
//     let content_block = Block::default()
//         .title("Content")
//         .borders(Borders::ALL)
//         .border_type(BorderType::Rounded);

//     let content_inner_area = content_block.inner(chunks[1]);
//     f.render_widget(content_block, chunks[1]); // Render the content block in the bottom chunk

//     // Your existing paragraph
//     let paragraph_text = "Look at this graph\n";
//     let paragraph = Paragraph::new(paragraph_text).wrap(Wrap { trim: true });

//     // Render the paragraph inside the content area
//     f.render_widget(paragraph, content_inner_area);
// }