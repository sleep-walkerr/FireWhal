#[derive(Debug, Default)]
pub struct App {
    pub screen: AppScreen,
}

#[derive(Debug)]
pub enum AppScreen {
    Main,
    Help,
}

impl Default for AppScreen {
    fn default() -> Self {
        AppScreen::Main
    }
}

impl App {
    pub fn next_screen(&mut self) {
        self.screen = match self.screen {
            AppScreen::Main => AppScreen::Help,
            AppScreen::Help => AppScreen::Main,
        };
    }
}