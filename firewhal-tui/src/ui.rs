pub mod main_menu;
pub mod debug_print;
pub mod app;
pub mod interface_selection;

use app::{App, AppScreen};
use ratatui::{prelude::*, Frame};

pub fn render(f: &mut Frame, app: &mut App) {
    match app.screen {
        AppScreen::MainMenu => main_menu::render(f, app),
        AppScreen::DebugPrint => debug_print::render(f, app),
        AppScreen::InterfaceSelection => interface_selection::render(f, app)
    }
}
