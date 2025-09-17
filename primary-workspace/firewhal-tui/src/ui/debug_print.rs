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
        .rev() // Show the most recent messages at the top
        .map(|msg| {
            let content = Line::from(Span::raw(msg.clone()));
            ListItem::new(content)
        })
        .collect();

    // Create a List widget
    let messages_list =
        List::new(messages).block(Block::default().borders(Borders::NONE));

    f.render_widget(messages_list, inner_area);
}