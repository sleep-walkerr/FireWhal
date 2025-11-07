pub mod main_menu;
pub mod debug_print;
pub mod app;
pub mod interface_selection;
pub mod permissive_mode;
pub mod rule_management;

use app::{App, AppScreen};
use ratatui::{prelude::*, Frame};

pub fn render(f: &mut Frame, app: &mut App) {
    match app.screen {
        AppScreen::MainMenu => main_menu::render(f, app),
        AppScreen::DebugPrint => debug_print::render(f, app),
        AppScreen::InterfaceSelection => interface_selection::render(f, app),
        AppScreen::PermissiveMode => permissive_mode::render(f, app),
        AppScreen::RuleManagement => rule_management::render(f, app),
    }
}
