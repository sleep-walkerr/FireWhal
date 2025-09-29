use ratatui::{prelude::*, widgets::*};
use crate::app::App;

pub fn render(f: &mut Frame, app: &App) {
    let block = Block::default()
        .title("IPC Debug Log")
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center)
        .border_type(BorderType::Rounded)
        .title_style(Style::default().fg(Color::LightBlue));

    let area = f.area();
    // We get the inner area from the block BEFORE we render it and move it.
    let inner_area = block.inner(area);
    // Now we can render the block.
    f.render_widget(block, area); // `block` is consumed here.

    // Convert the Vec<String> from the app state into a Vec<ListItem> for the widget.
    let messages: Vec<ListItem> = app
        .debug_messages
        .iter()
        .rev() // Show the most recent messages at the bottom of the view (top of the list)
        .map(|msg| {
            // Style the message based on its source component
            let (source, content) = msg.split_once(": ").unwrap_or(("System", msg));
            let source_style = match source {
                "[Daemon]" => Style::default().fg(Color::Cyan),
                "[Firewall]" => Style::default().fg(Color::Red),
                "[Discord]" => Style::default().fg(Color::Blue),
                _ => Style::default().fg(Color::Yellow),
            };

            let line = Line::from(vec![
                Span::styled(source, source_style.bold()),
                Span::raw(": "),
                Span::styled(content, Style::default().fg(Color::White)),
            ]);

            ListItem::new(line)
        })
        .collect();

    // Create a List widget
    let messages_list = List::new(messages)
        .block(Block::default().borders(Borders::NONE))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_widget(messages_list, inner_area);
}