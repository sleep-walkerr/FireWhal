/*
Have a Narwhal made of fire slide downwards from a singular line on the screen
*/

use ratatui::{prelude::*, widgets::*};

pub fn render(f: &mut Frame) {
    let block = Block::default()
        .title("FireWhal")
        .borders(Borders::ALL)
        .title_alignment(Alignment::Center)
        .border_type(BorderType::Rounded)
        ;

    let area = f.area();
    let inner_area = block.inner(area);
    f.render_widget(block, area); // block is moved here after .inner() is called

    let paragraph_text = "Look at this graph\n";

    let paragraph = Paragraph::new(paragraph_text)
    .wrap(Wrap {trim : true});

    f.render_widget(paragraph, inner_area);

}