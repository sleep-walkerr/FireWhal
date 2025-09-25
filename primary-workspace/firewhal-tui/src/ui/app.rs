use std::time::Instant;
#[derive(Debug)]
pub struct App<'a> {
    pub titles: Vec<&'a str>,
    pub screen: AppScreen,
    pub index: usize,
    pub progress: f64, // New: Current progress for the gauge (0.0 to 1.0)
    pub progress_direction: i8, // New: 1 for increasing, -1 for decreasing
    pub last_tick: Instant, // New: To control animation speed
    pub debug_messages: Vec<String>, // To store messages from IPC
}

#[derive(Debug)]
pub enum AppScreen {
    MainMenu,
    DebugPrint,
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
            AppScreen::DebugPrint => AppScreen::MainMenu,
        };
        self.index = (self.index + 1) % self.titles.len();
    }

    pub fn add_debug_message(&mut self, message: String) {
        self.debug_messages.push(message);
        // To prevent the list from growing indefinitely, we can cap its size.
        const MAX_MESSAGES: usize = 100;
        if self.debug_messages.len() > MAX_MESSAGES {
            // Removes the oldest message
            self.debug_messages.remove(0);
        }
    }

    pub fn update_progress(&mut self) {
        self.progress += (self.progress_direction as f64) * 0.01; // Adjust speed as needed

        // make this random later
        if self.progress >= 1.0 {
            self.progress = 1.0;
            self.progress_direction = -1;
        } else if self.progress <= 0.0 {
            self.progress = 0.0;
            self.progress_direction = 1;
        }
    }
}

impl Default for App<'_> {
    fn default() -> Self {
        App {
            screen: AppScreen::default(),
            titles: vec![
                "Status",
                "Rule Management",
                "Notifications",
                "Active Connections",
            ],
            index: 0,
            progress: 0.0,
            progress_direction: 1,
            last_tick: Instant::now(), // Manually initialize `last_tick`
            debug_messages: Vec::new(),
        }
    }
}