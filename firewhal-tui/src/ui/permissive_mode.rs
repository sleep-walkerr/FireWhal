use std::collections::HashSet;

use ratatui::{prelude::*, widgets::*};
use crossterm::event::KeyCode;
use tokio::sync::mpsc;
use firewhal_core::{FireWhalMessage, UpdateInterfaces};
use crate::ui::app::App;

#[derive(Debug, Default)]
pub struct ProcessLineageTupleList {
    process_lineage_tuple_list: Vec<(String, String)>,
}

impl ProcessLineageTupleList {
 pub fn add_tuple(&mut self, tuple: (String, String)) {
    self.process_lineage_tuple_list.push(tuple);
 }
 pub fn clear_interfaces(&mut self) {
    self.process_lineage_tuple_list.clear();
 }
 pub fn is_empty(&self) -> bool { // Use pre-existing function
    self.process_lineage_tuple_list.is_empty()
 }
 pub fn len(&self) -> usize { // Use pre-existing function
    self.process_lineage_tuple_list.len()
 }
 pub fn get(&self, index: usize) -> Option<&(String, String)> { // Use pre-existing function
    self.process_lineage_tuple_list.get(index)
 }
 pub fn iter(&self) -> std::slice::Iter<(String, String)> { // Use pre-existing function
    self.process_lineage_tuple_list.iter()
 }
}

#[derive(Debug, Default)]
pub struct ToggledPaths {
    toggled_paths: HashSet<String>
}

impl ToggledPaths {
    pub fn insert(&mut self, interface: String) {
        self.toggled_paths.insert(interface);
    }
    pub fn remove(&mut self, interface: &str) -> bool {
        self.toggled_paths.remove(interface)
    } 
    pub fn iter(&self) -> std::collections::hash_set::Iter<String> {
        self.toggled_paths.iter()
    }
    pub fn contains(&self, interface: &str) -> bool {
        self.toggled_paths.contains(interface)
    }
}

#[derive(Debug, Default, Clone)]
pub struct PermissiveListState {
    permissive_list_state: ListState
}

impl PermissiveListState {
    pub fn select(&mut self, index: Option<usize>) {
        self.permissive_list_state.select(index);
    }
    pub fn selected(&self) -> Option<usize> {
        self.permissive_list_state.selected()
    }
}



// User input processing
pub fn handle_key_event(key_code: KeyCode, app: &mut App) {
    match key_code {
        KeyCode::Up => {
            if !app.process_lineage_tuple_list.process_lineage_tuple_list.is_empty() {
                let current_selection = app.permissive_mode_list_state.selected().unwrap_or(0);
                let new_selection = current_selection.saturating_sub(1); // wrap around
                app.permissive_mode_list_state.select(Some(new_selection));
            }
        }
        KeyCode::Down => {
            if !app.process_lineage_tuple_list.process_lineage_tuple_list.is_empty() {
                let current_selection = app.permissive_mode_list_state.selected().unwrap_or(0);
                let new_selection = (current_selection + 1).min(app.process_lineage_tuple_list.process_lineage_tuple_list.len() - 1);
                app.permissive_mode_list_state.select(Some(new_selection));
            }
        }
        // KeyCode::Char(' ') => {
        //     if let Some(selected_index) = app.permissive_mode_list_state.selected() {
        //         if let Some(selected_interface) = app.process_lineage_tuple_list.process_lineage_tuple_list.get(selected_index) {
        //             // If the interface is already toggled, untoggle it. Otherwise, toggle it.
        //             if !app.toggled_paths.remove(selected_interface.as_str()) {
        //                 app.toggled_paths.insert(selected_interface.clone());
        //             }
        //         }
        //     }
        // }
        KeyCode::Enter => {
            let selected_paths: Vec<String> = app.toggled_paths.iter().cloned().collect();
            // let msg = FireWhalMessage::UpdateInterfaces(UpdateInterfaces { source: ("TUI".to_string()), interfaces: (selected_paths) });
            
            // // Send interface selection message to firewhal-kernel
            // if let Some(zmq_sender) = &app.to_zmq_tx {
            //     if let Err(e) = zmq_sender.try_send(msg) {
            //         let _ = &app.debug_print.add_message(format!("Failed to send UpdateInterfaces message: {}", e));
            //     } 
            // } else { let _ = &app.debug_print.add_message("Interface Selection found no zmq sender".to_string()); }
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
    let items: Vec<ListItem> = app.process_lineage_tuple_list
        .iter()
        .map(|iface_name| {
            // Check if the current interface is in the toggled set
            // let is_toggled = app.toggled_paths.contains(iface_name);
            
            // let prefix = if is_toggled { "[x] " } else { "[ ] " };
            // let style = if is_toggled {
            //     Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            // } else {
            //     Style::default()
            // };

            ListItem::new(format!("{} : {}", iface_name.0, iface_name.1))
        })
        .collect();

    let list_widget = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Select Paths (Space to toggle, Enter to apply)"))
        .highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(">> ");

    // We pass a mutable reference to the ListState to the render function
    let mut list_state = app.permissive_mode_list_state.clone();
    f.render_stateful_widget(list_widget, f.area(), &mut list_state.permissive_list_state);
}