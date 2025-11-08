use ratatui::{prelude::*, widgets::*};
use crossterm::event::{KeyCode, KeyEvent};
use firewhal_core::{FireWhalConfig, FireWhalMessage, Rule, Action, Protocol};
use crate::ui::app::App;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;


pub fn render(f: &mut Frame, app: &mut App) {
    let area = f.area();
    
}

