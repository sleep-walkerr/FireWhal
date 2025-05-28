use ratatui::{prelude::*, widgets::*};

pub fn render(f: &mut Frame) {
    let block = Block::default()
        .title("Main Screen")
        .borders(Borders::ALL);
    f.render_widget(block, f.area());
}