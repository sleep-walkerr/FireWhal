use std::collections::HashSet;

use color_eyre::owo_colors::OwoColorize;
use ratatui::{prelude::*, widgets::*, widgets::block::Title};
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
    // Create a sorted list of interfaces to ensure consistent ordering for navigation
    let mut sorted_interfaces: Vec<_> = app.available_interfaces.iter().cloned().collect();
    sorted_interfaces.sort();

    match key_code {
        KeyCode::Up => {
            if !sorted_interfaces.is_empty() {
                let current_selection = match app.interface_list_state.selected() {
                    Some(i) => i,
                    None => 0, // Default to first item if nothing is selected
                };
                let new_selection = current_selection.saturating_sub(1); // wrap around
                app.interface_list_state.select(Some(new_selection));
            }
        }
        KeyCode::Down => {
            if !sorted_interfaces.is_empty() {
                let current_selection = match app.interface_list_state.selected() {
                    Some(i) => i,
                    None => {
                        0 // Default to first item if nothing is selected
                    }
                };
                let new_selection = (current_selection + 1).min(sorted_interfaces.len() - 1);
                app.interface_list_state.select(Some(new_selection));
            }
        }
        KeyCode::Char(' ') => {
            if let Some(selected_index) = app.interface_list_state.selected() {
                if let Some(selected_interface) = sorted_interfaces.get(selected_index) {
                    // If the interface is already toggled, untoggle it. Otherwise, toggle it.
                    if !app.toggled_interfaces.remove(selected_interface) {
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

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    // Create a Title with its own style, independent of the border
    let title = Title::from(" Select Interfaces (Space to toggle, Enter to apply) ")
        .content.style(Style::default().fg(Color::Reset));

    let outer_block = Block::default()
        .borders(Borders::ALL)
        .title(title) // Pass the explicitly styled Title
        // Style the border to be blue
        .border_style(Style::default().fg(Color::Blue));
    let inner_area = outer_block.inner(area);
    f.render_widget(outer_block, area);

    // Create a sorted list of interfaces to ensure consistent ordering for rendering
    let mut sorted_interfaces: Vec<_> = app.available_interfaces.iter().cloned().collect();
    sorted_interfaces.sort();

    if sorted_interfaces.is_empty() {
        return;
    }

    let num_items = sorted_interfaces.len();
    let constraints: Vec<Constraint> = std::iter::repeat(Constraint::Length(3)).take(num_items).collect();
    let rows_layout = Layout::vertical(constraints).split(inner_area);

    let selected_index = app.interface_list_state.selected();

    for (i, iface_name) in sorted_interfaces.iter().enumerate() {
        let row_area = rows_layout[i];
        // Create a centered area that is 50% of the row's width
        let centered_row_area = Layout::horizontal([
            Constraint::Percentage(38), // (100 - 25) / 2, rounded up
            Constraint::Percentage(25),
            Constraint::Percentage(37), // (100 - 25) / 2, rounded down
        ]).split(row_area)[1];

        // An item is only visually selected if the content pane has focus
        let is_selected = if !app.focus_on_navigation {
            selected_index == Some(i)
        } else {
            false
        };
        let is_toggled = app.toggled_interfaces.contains(iface_name);

        // Determine styles based on toggled and selected state
        let mut border_style = if is_toggled {
            // Toggled: Green border
            Style::default().fg(Color::Green)
        } else {
            // Untoggled: Gray border
            Style::default().fg(Color::DarkGray)
        };

        // All interface text is blue by default
        let mut iface_style = Style::default().fg(Color::Blue);

        // Selected items get a blue border and white text to stand out
        if is_selected {
            border_style = Style::default().fg(Color::Blue); // Override border color
            iface_style = Style::default(); // Override text color
        }

        let border_type = BorderType::Rounded; // All items are rounded

        let item_block = Block::default()
            .borders(Borders::ALL)
            .border_type(border_type)
            .border_style(border_style);

        // Get the inner area of the block to create a new layout inside it
        let inner_block_area = item_block.inner(centered_row_area);

        // Split the inner area to align the component name and status separately
        let inner_chunks = Layout::horizontal([
            Constraint::Percentage(50), // Left side for interface name
            Constraint::Percentage(50), // Right side for status
        ]).split(inner_block_area);

        let (status_text, status_style) = if is_toggled {
            ("Active", Style::default().fg(Color::Green))
        } else {
            ("Inactive", Style::default().fg(Color::Red))
        };

        // Interface name paragraph (right-aligned)
        let iface_line = Line::from(vec![
            Span::styled(iface_name.clone(), iface_style),
            Span::styled(" :", Style::default()),
        ]);
        let iface_paragraph = Paragraph::new(iface_line).right_aligned();


        // Status paragraph (left-aligned)
        let status_paragraph = Paragraph::new(Span::styled(format!(" {}", status_text), status_style))
            .left_aligned();

        f.render_widget(item_block, centered_row_area);
        f.render_widget(iface_paragraph, inner_chunks[0]);
        f.render_widget(status_paragraph, inner_chunks[1]);
    }
}