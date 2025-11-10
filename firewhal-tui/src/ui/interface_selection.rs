use std::collections::HashSet;

use ratatui::{prelude::*, widgets::*};
use crossterm::event::KeyCode;
use tokio::sync::mpsc;
use firewhal_core::{FireWhalMessage, UpdateInterfaces};
use crate::ui::app::App;

#[derive(Debug, Default)]
pub struct InterfaceList {
    interfaces: Vec<String>,
}

impl InterfaceList {
 pub fn add_interface(&mut self, interface: String) {
    self.interfaces.push(interface);
 }
 pub fn clear_interfaces(&mut self) {
    self.interfaces.clear();
 }
 pub fn is_empty(&self) -> bool { // Use pre-existing function
    self.interfaces.is_empty()
 }
 pub fn len(&self) -> usize { // Use pre-existing function
    self.interfaces.len()
 }
 pub fn get(&self, index: usize) -> Option<&String> { // Use pre-existing function
    self.interfaces.get(index)
 }
 pub fn iter(&self) -> std::slice::Iter<String> { // Use pre-existing function
    self.interfaces.iter()
 }
}

#[derive(Debug, Default)]
pub struct ToggledInterfaces {
    toggled_interfaces: HashSet<String>
}

impl ToggledInterfaces {
    pub fn insert(&mut self, interface: String) {
        self.toggled_interfaces.insert(interface);
    }
    pub fn remove(&mut self, interface: &str) -> bool {
        self.toggled_interfaces.remove(interface)
    } 
    pub fn iter(&self) -> std::collections::hash_set::Iter<String> {
        self.toggled_interfaces.iter()
    }
    pub fn contains(&self, interface: &str) -> bool {
        self.toggled_interfaces.contains(interface)
    }
}

#[derive(Debug, Default, Clone)]
pub struct InterfaceListState {
    interface_list_state: ListState
}

impl InterfaceListState {
    pub fn select(&mut self, index: Option<usize>) {
        self.interface_list_state.select(index);
    }
    pub fn selected(&self) -> Option<usize> {
        self.interface_list_state.selected()
    }
}



// User input processing
pub fn handle_key_event(key_code: KeyCode, app: &mut App) {
    match key_code {
        KeyCode::Up => {
            if !app.available_interfaces.is_empty() {
                let current_selection = app.interface_list_state.selected().unwrap_or(0);
                let new_selection = current_selection.saturating_sub(1); // wrap around
                app.interface_list_state.select(Some(new_selection));
            }
        }
        KeyCode::Down => {
            if !app.available_interfaces.is_empty() {
                let current_selection = app.interface_list_state.selected().unwrap_or(0);
                let new_selection = (current_selection + 1).min(app.available_interfaces.len() - 1);
                app.interface_list_state.select(Some(new_selection));
            }
        }
        KeyCode::Char(' ') => {
            if let Some(selected_index) = app.interface_list_state.selected() {
                if let Some(selected_interface) = app.available_interfaces.get(selected_index) {
                    // If the interface is already toggled, untoggle it. Otherwise, toggle it.
                    if !app.toggled_interfaces.remove(selected_interface.as_str()) {
                        app.toggled_interfaces.insert(selected_interface.clone());
                    }
                }
            }
        }
        KeyCode::Enter => {
            let selected_interfaces: HashSet<String> = app.toggled_interfaces.iter().cloned().collect();
            let msg = FireWhalMessage::UpdateInterfaces(UpdateInterfaces { source: ("TUI".to_string()), interfaces: (selected_interfaces) });
            
            // Send interface selection message to firewhal-kernel
            if let Some(zmq_sender) = &app.to_zmq_tx {
                if let Err(e) = zmq_sender.try_send(msg) {
                    let _ = &app.debug_print.add_message(format!("Failed to send UpdateInterfaces message: {}", e));
                } 
            } else { let _ = &app.debug_print.add_message("Interface Selection found no zmq sender".to_string()); }
        }
        _ => {}
    }
}

pub fn render(f: &mut Frame, app: &App) {
    

    // let block = Block::default()
    //     .title("Interface Selection")
    //     .borders(Borders::ALL)
    //     .title_alignment(Alignment::Center)
    //     .border_type(BorderType::Rounded)
    //     .title_style(Style::default().fg(Color::LightBlue));

    // let area = f.area();
    // // We get the inner area from the block BEFORE we render it and move it.
    // let inner_area = block.inner(area);
    // // Now we can render the block.
    // f.render_widget(block, area); // `block` is consumed here.

    // Create a list of `ListItem`s from your data
    let items: Vec<ListItem> = app.available_interfaces
        .iter()
        .map(|iface_name| {
            // Check if the current interface is in the toggled set
            let is_toggled = app.toggled_interfaces.contains(iface_name);
            
            let prefix = if is_toggled { "[x] " } else { "[ ] " };
            let style = if is_toggled {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(format!("{}{}", prefix, iface_name)).style(style)
        })
        .collect();

    let list_widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Select Interfaces (Space to toggle, Enter to apply)"))
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(">> ");

    // We pass a mutable reference to the ListState to the render function
    let mut list_state = app.interface_list_state.clone();
    f.render_stateful_widget(list_widget, f.area(), &mut list_state.interface_list_state);
}