use std::collections::HashMap;

use crate::ui::{
    app_management::AppListState,
    debug_print::DebugPrintState,
    interface_selection::{InterfaceList, InterfaceListState, ToggledInterfaces},
    main_menu::MainMenuState,
    permissive_mode::{PermissiveListState, ProcessLineageTupleList, ToggledPaths},
    rule_management::RuleTableState,
    state_view::StateViewState,
};
use firewhal_core::{AppIdentity, DefaultVerdict, FireWhalConfig, FireWhalMessage, Rule};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppScreen {
    MainMenu,
    InterfaceSelection,
    OutgoingRules,
    IncomingRules,
    AppManagement,
    PermissiveMode,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashState {
    Unchecked,
    Valid,
    Invalid,
}

impl AppScreen {
    pub fn display_name(&self) -> &'static str {
        match self {
            AppScreen::MainMenu => "Status",
            AppScreen::InterfaceSelection => "Active Interfaces",
            AppScreen::OutgoingRules => "Outgoing Rules",
            AppScreen::IncomingRules => "Incoming Rules",
            AppScreen::AppManagement => "App Management",
            AppScreen::PermissiveMode => "Permissive Detection",
            AppScreen::Debug => "Debug",
        }
    }
}
#[derive(Debug)]
pub struct App {
    pub screen: AppScreen,
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
    pub outgoing_rule_state: RuleTableState,
    pub incoming_rule_state: RuleTableState,
    pub rules_modified: bool,
    pub rules: Vec<Rule>, // Outgoing rules
    pub incoming_rules: Vec<Rule>,
    // #159: per-direction default verdicts (UI controls land in PR 2; for
    // now these round-trip from RulesResponse into UpdateRules).
    pub default_incoming: DefaultVerdict,
    pub default_outgoing: DefaultVerdict,
    pub app_list_state: AppListState,
    pub apps_modified: bool,
    pub apps: HashMap<String, AppIdentity>,
    pub hash_states: HashMap<String, HashState>,
    // #182: state introspection (in-kernel maps + attach state + C1 health)
    pub state_view: StateViewState,

    // New UI state
    pub nav_index: usize,
    pub nav_items: Vec<AppScreen>,
    pub focus_on_navigation: bool,
}

impl Default for AppScreen {
    fn default() -> Self {
        AppScreen::MainMenu
    }
}

impl App {
    pub fn select_next_nav_item(&mut self) {
        self.nav_index = (self.nav_index + 1) % self.nav_items.len();
        self.screen = self.nav_items[self.nav_index];
        self.focus_on_navigation = true;
    }

    pub fn select_prev_nav_item(&mut self) {
        if self.nav_index > 0 {
            self.nav_index -= 1;
        } else {
            self.nav_index = self.nav_items.len() - 1;
        }
        self.screen = self.nav_items[self.nav_index];
        self.focus_on_navigation = true;
    }

    // This method is now repurposed to toggle focus between navigation and content
    pub fn next_screen(&mut self) {
        self.focus_on_navigation = !self.focus_on_navigation;
        if !self.focus_on_navigation {
            self.screen = self.nav_items[self.nav_index]; // Ensure screen is set when focusing content
        }
    }

    /// #182: asks the kernel for a point-in-time snapshot of its in-kernel
    /// state (and the daemon for the C1 config-health view).
    pub fn request_state(&mut self) {
        if let Some(tx) = &self.to_zmq_tx {
            if let Err(e) = tx.try_send(FireWhalMessage::StateRequest(firewhal_core::TUIStateRequest {
                component: "TUI".to_string(),
            })) {
                self.debug_print.add_message(format!("[TUI] Failed to send StateRequest: {e}"));
            }
        } else {
            self.debug_print.add_message("[TUI] StateRequest: found no zmq sender".to_string());
        }
    }

    /// Sends the complete, current list of rules to the daemon.
    pub fn send_rules_to_daemon(&mut self) {
        let config = FireWhalConfig {
            outgoing_rules: self.rules.clone(),
            incoming_rules: self.incoming_rules.clone(),
            default_incoming: self.default_incoming,
            default_outgoing: self.default_outgoing,
        };
        if let Some(tx) = &self.to_zmq_tx {
            if let Err(e) = tx.try_send(FireWhalMessage::UpdateRules(config)) {
                self.debug_print.add_message(format!("[TUI] Failed to send rules to daemon: {}", e));
            } else {
                self.debug_print.add_message("[TUI] Sent rules to daemon.".to_string());
                self.rules_modified = false;
            }
        }
    }
}

impl Default for App {
    fn default() -> Self {
        let nav_items = vec![
            AppScreen::MainMenu,
            AppScreen::InterfaceSelection,
            AppScreen::OutgoingRules,
            AppScreen::IncomingRules,
            AppScreen::AppManagement,
            AppScreen::PermissiveMode,
            AppScreen::Debug,
        ];
        let initial_screen = nav_items.first().cloned().unwrap_or_default();

        App {
            to_zmq_tx: None,
            screen: initial_screen,

            // Screen states
            main_menu: MainMenuState::default(),
            debug_print: DebugPrintState::default(),
            available_interfaces: InterfaceList::default(),
            interface_list_state: InterfaceListState::default(),
            toggled_interfaces: ToggledInterfaces::default(),

            permissive_mode_list_state: PermissiveListState::default(),
            process_lineage_tuple_list: ProcessLineageTupleList::default(),
            toggled_paths: ToggledPaths::default(),
            outgoing_rule_state: RuleTableState::default(),
            incoming_rule_state: RuleTableState::default(),
            rules_modified: false,
            rules: Vec::new(),
            incoming_rules: Vec::new(),
            default_incoming: DefaultVerdict::Block,
            default_outgoing: DefaultVerdict::Block,
            app_list_state: AppListState::default(),
            apps_modified: false,
            apps: HashMap::new(),
            hash_states: HashMap::new(),
            state_view: StateViewState::default(),

            // UI state
            nav_index: 0,
            nav_items,
            focus_on_navigation: true,
        }
    }
}