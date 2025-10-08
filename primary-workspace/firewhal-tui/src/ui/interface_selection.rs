use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;

#[derive(Debug, Default)]
pub struct InterfaceList {
    interfaces: Vec<String>,
}

impl InterfaceList {
 pub fn add_interface(&mut self, interface: String) {
    self.interfaces.push(interface);
 }
}

pub fn render(f: &mut Frame, app: &App) {
    

    let block = Block::default()
        .title("Interface Selection")
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
        .interface_selection
        .interfaces
        .iter()
        .map(|msg| {
            // Style the message based on its source component
            let line = Line::from(vec![
                Span::styled(msg, Style::default().fg(Color::Yellow)),
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