use std::time::Instant;
use crate::ui::{debug_print::DebugPrintState, main_menu::MainMenuState, interface_selection::InterfaceList};
use tokio::sync::mpsc;
use firewhal_core::FireWhalMessage;

#[derive(Debug)]
pub struct App<'a> {
    pub titles: Vec<&'a str>,
    pub screen: AppScreen,
    pub index: usize,
    pub to_zmq_tx: Option<mpsc::Sender<FireWhalMessage>>,

    // Screen-specific states
    pub main_menu: MainMenuState,
    pub debug_print: DebugPrintState,
    pub interface_selection: InterfaceList,
}

#[derive(Debug)]
pub enum AppScreen {
    MainMenu,
    DebugPrint,
    InterfaceSelection
}

impl Default for AppScreen {
    fn default() -> Self {
        AppScreen::MainMenu
    }
}

impl<'a> App<'a> {
    pub fn next_screen(&mut self) {
        self.screen = match self.screen {
            AppScreen::MainMenu => AppScreen::DebugPrint,
            AppScreen::DebugPrint => AppScreen::InterfaceSelection,
            AppScreen::InterfaceSelection => AppScreen::MainMenu
        };
        self.index = (self.index + 1) % self.titles.len();
    }
}

impl Default for App<'_> {
    fn default() -> Self {
        App {
            to_zmq_tx: None,
            screen: AppScreen::default(),
            titles: vec![
                "Status",
                "Rule Management",
                "Notifications",
                "Active Connections",
            ],
            index: 0,
            main_menu: MainMenuState::default(),
            debug_print: DebugPrintState::default(),
            interface_selection: InterfaceList::default()
        }
    }
}