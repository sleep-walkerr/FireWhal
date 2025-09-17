pub mod main_menu;
pub mod splash;
pub mod app;

use crate::app::{App, AppScreen};
use ratatui::{prelude::*, Frame};

pub fn render(f: &mut Frame, app: &App) {
    match app.screen {
        AppScreen::MainMenu => main_menu::render(f, app),
        AppScreen::Splash => splash::render(f, app),
    }
}

