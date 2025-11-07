use std::collections::HashMap;
use std::ops::Deref;
use ratatui::{prelude::*, widgets::*};
use crossterm::event::{KeyCode, KeyEvent};
use tokio::sync::mpsc;
use firewhal_core::{FireWhalMessage, UpdateInterfaces};
use crate::ui::app::App;

#[derive(Debug, Default)]
pub struct RuleList {
    rule_list: Vec<Vec<(String, String)>>,
}

impl Deref for RuleList {
    type Target = Vec<Vec<(String, String)>>;

    fn deref(&self) -> &Self::Target {
        &self.rule_list
    }
}

pub fn render(f: &mut Frame, app: &App) {

}