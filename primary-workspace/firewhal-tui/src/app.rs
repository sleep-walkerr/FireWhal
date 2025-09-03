#[derive(Debug, Default)]
pub struct App {
    pub screen: AppScreen,
}

#[derive(Debug)]
pub enum AppScreen {
    MainMenu,
    //Splash,
}

impl Default for AppScreen {
    fn default() -> Self {
        AppScreen::MainMenu
    }
}

// impl App {
//     pub fn next_screen(&mut self) {
//         self.screen = match self.screen {
//             //AppScreen::MainMenu => AppScreen::Splash
//             AppScreen::Splash => AppScreen::MainMenu,
//         };
//     }
// }