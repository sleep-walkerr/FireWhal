use std::time::Instant;
use crate::ui::{
    app_management::AppListState,
    debug_print::DebugPrintState, 
    interface_selection::{InterfaceList, InterfaceListState, ToggledInterfaces}, 
    main_menu::MainMenuState, 
    permissive_mode::{PermissiveListState, ProcessLineageTupleList, ToggledPaths},
    rule_management::{RuleListState, RuleManagementMode}
};
use tokio::sync::mpsc;
use firewhal_core::{FireWhalMessage, AppIdentity};

#[derive(Debug)]
pub struct App<'a> {
    pub titles: Vec<&'a str>,
    pub screen: AppScreen,
    pub index: usize,
    pub to_zmq_tx: Option<mpsc::Sender<FireWhalMessage>>,

    // Screen-specific states
    //Check and see if irrelevant data is being used on unreleated screens
    pub main_menu: MainMenuState,
    pub debug_print: DebugPrintState,
    pub available_interfaces: InterfaceList,
    pub interface_list_state: InterfaceListState,
    pub toggled_interfaces: ToggledInterfaces,
    pub process_lineage_tuple_list: ProcessLineageTupleList,
    pub permissive_mode_list_state: PermissiveListState,
    pub toggled_paths: ToggledPaths,
    pub rule_list_state: RuleListState,
    pub rules_modified: bool,
    pub rules: Vec<firewhal_core::Rule>,
    pub app_list_state: AppListState,
    pub apps_modified: bool,
    pub apps: Vec<(String, AppIdentity)>,
}

#[derive(Debug)]
pub enum AppScreen {
    MainMenu,
    DebugPrint,
    InterfaceSelection,
    PermissiveMode,
    RuleManagement,
    AppManagement
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
            AppScreen::InterfaceSelection => AppScreen::PermissiveMode,
            AppScreen::PermissiveMode => AppScreen::RuleManagement,
            AppScreen::RuleManagement => AppScreen::AppManagement,
            AppScreen::AppManagement => AppScreen::MainMenu
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
            available_interfaces: InterfaceList::default(),
            interface_list_state: InterfaceListState::default(),
            toggled_interfaces: ToggledInterfaces::default(),
            permissive_mode_list_state: PermissiveListState::default(),
            process_lineage_tuple_list: ProcessLineageTupleList::default(),
            toggled_paths: ToggledPaths::default(),
            rule_list_state: RuleListState::default(),
            rules_modified: false,
            rules: Vec::new(),
            app_list_state: AppListState::default(),
            apps_modified: false,
            apps: Vec::new(),
        }
    }
}