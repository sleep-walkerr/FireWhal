use ratatui::{prelude::*, widgets::*};
use crate::ui::app::App;

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

    // // Create a List widget
    // let messages_list = List::new(interface_list)
    //     .block(Block::default().borders(Borders::NONE))
    //     .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
    //     .highlight_symbol(">> ");

    // f.render_widget(messages_list, inner_area);
}