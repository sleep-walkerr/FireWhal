/*
Add usage bars showing how much traffic is flowing for IPv4 and IPv6
Show basic status of each subapp, for now each will show inactive


*/
use ratatui::{prelude::*, widgets::*};

pub fn render(f: &mut Frame) {
    // 1. Create individual styled parts of the title
    let firewhal_span = Span::styled(
        "FireWhal ",
        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
    );
    let icon_span = Span::styled(
        "",
        Style::default().fg(Color::Rgb(255, 165, 0)), // A nice orange color
    );

    // 2. Combine the parts into a single `Line`
    let title = Line::from(vec![firewhal_span, icon_span]);

    // 3. Use the `Line` as the title for the main block
    let main_block = Block::default()
        .title(title) // The multi-colored title is now used here
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center)
        .border_type(BorderType::Rounded);

    // Get the inner area from main_block *before* it's moved.
    let main_inner_area = main_block.inner(f.area());
    // Now, render the main_block.
    f.render_widget(main_block, f.area());

    // Create a layout to split the area inside the main block
    let chunks = Layout::vertical([
        Constraint::Length(3), // A fixed-height chunk for the tabs
        Constraint::Min(0),    // The rest of the space for content
    ])
    .split(main_inner_area);

    // Define the tab titles
    let titles = vec!["Status", "Rule Management", "Notifications", "Active Connections"];
    let tabs = Tabs::new(titles)
        .block(Block::default().title("Navigation").borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .select(0);

    // Render the tabs in the top chunk
    f.render_widget(tabs, chunks[0]);

    // Your existing content block
    let content_block = Block::default()
        .title("Content")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);

    let content_inner_area = content_block.inner(chunks[1]);
    f.render_widget(content_block, chunks[1]); // Render the content block in the bottom chunk

    // Your existing paragraph
    let paragraph_text = "Look at this graph\n";
    let paragraph = Paragraph::new(paragraph_text).wrap(Wrap { trim: true });

    // Render the paragraph inside the content area
    f.render_widget(paragraph, content_inner_area);
}