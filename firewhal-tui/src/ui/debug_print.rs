use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;

#[derive(Debug, Default)]
pub struct DebugPrintState {
    messages: Vec<String>,
}

impl DebugPrintState {
    pub fn add_message(&mut self, message: String) {
        self.messages.push(message);
        // To prevent the list from growing indefinitely, we can cap its size.
        const MAX_MESSAGES: usize = 100;
        if self.messages.len() > MAX_MESSAGES {
            // Removes the oldest message
            self.messages.remove(0);
        }
    }
}

pub fn render(f: &mut Frame, app: &mut App) {
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
    let list_items: Vec<ListItem> = app
        .debug_print
        .messages
        .iter()
        .rev() // Show the most recent messages at the bottom of the view (top of the list)
        .map(|msg| {
            // Style the message based on its source component
            let (source, content) = msg.split_once(": ").unwrap_or(("System", msg));
            let source_style = match source {
                "[Daemon]" => Style::default().fg(Color::Cyan),
                "[Firewall]" => Style::default().fg(Color::Red),
                "[DiscordBot]" => Style::default().fg(Color::Blue),
                "[IPC]" => Style::default().fg(Color::Magenta),
                "[TUI]" => Style::default().fg(Color::LightGreen),
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
    let messages_list = List::new(list_items)
        .block(Block::default().borders(Borders::NONE))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

    f.render_widget(messages_list, inner_area);
}