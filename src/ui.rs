pub mod main_menu;
pub mod splash;

use crate::app::{App, AppScreen};
use ratatui::{prelude::*, Frame};

pub fn render(f: &mut Frame, app: &App) {
    match app.screen {
        AppScreen::Main => main_menu::render(f),
        AppScreen::Help => splash::render(f),
    }
}

