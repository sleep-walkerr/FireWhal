use std::collections::HashMap;

use ratatui::{prelude::*, widgets::*};
use crossterm::event::{KeyCode, KeyEvent};
use tokio::sync::mpsc;
use firewhal_core::{FireWhalMessage, UpdateInterfaces};
use crate::ui::app::App;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ActivePanel {
    Lineages,
    Processes,
}


#[derive(Debug, Default)]
pub struct ProcessLineageTupleList {
    process_lineage_tuple_list: Vec<Vec<(String, String)>>,
}

impl ProcessLineageTupleList {
 pub fn add_tuple(&mut self, tuple: Vec<(String, String)>) {
    if !self.process_lineage_tuple_list.contains(&tuple) {
        self.process_lineage_tuple_list.push(tuple);
    }
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
 pub fn get(&self, index: usize) -> Option<&(Vec<(String, String)>)> { // Use pre-existing function
    self.process_lineage_tuple_list.get(index)
 }
 pub fn iter(&self) -> std::slice::Iter<Vec<(String, String)>> { // Use pre-existing function
    self.process_lineage_tuple_list.iter()
 }
}

#[derive(Debug, Default)]
pub struct ToggledPaths {
    toggled_paths: HashMap<String, String>
}

impl ToggledPaths {
    pub fn insert(&mut self, path: String, hash: String) {
        self.toggled_paths.insert(path, hash);
    }
    pub fn remove(&mut self, path: &str) -> Option<String>{
        self.toggled_paths.remove(path)
    } 
    pub fn iter(&self) -> std::collections::hash_map::Iter<String, String> {
        self.toggled_paths.iter()
    }
    pub fn contains(&self, path: &str) -> bool {
        self.toggled_paths.contains_key(path)
    }
}

#[derive(Debug, Default, Clone)]
pub struct PermissiveListState {
    pub lineage_list_state: ListState,
    pub process_list_state: ListState,
    pub active_panel: ActivePanel,
}

impl PermissiveListState {
    pub fn selected_lineage(&self) -> Option<usize> {
        self.lineage_list_state.selected()
    }
}

impl Default for ActivePanel {
    fn default() -> Self {
        ActivePanel::Lineages
    }
}



// User input processing
pub fn handle_key_event(key_code: KeyCode, app: &mut App) {
    let state = &mut app.permissive_mode_list_state;
    match state.active_panel {
        ActivePanel::Lineages => match key_code {
            KeyCode::Up => {
                if !app.process_lineage_tuple_list.is_empty() {
                    let current_selection = state.lineage_list_state.selected().unwrap_or(0);
                    let new_selection = current_selection.saturating_sub(1);
                    state.lineage_list_state.select(Some(new_selection));
                    // Reset process list selection when lineage changes
                    state.process_list_state.select(Some(0));
                }
            }
            KeyCode::Down => {
                if !app.process_lineage_tuple_list.is_empty() {
                    let i = state.lineage_list_state.selected().unwrap_or(0);
                    if i < app.process_lineage_tuple_list.len() - 1 {
                        state.lineage_list_state.select(Some(i + 1));
                        // Reset process list selection when lineage changes
                        state.process_list_state.select(Some(0));
                    }
                }
            }
            KeyCode::Right | KeyCode::Tab => {
                state.active_panel = ActivePanel::Processes;
            }
            _ => {}
        },
        ActivePanel::Processes => match key_code {
            KeyCode::Up => {
                if let Some(lineage_idx) = state.lineage_list_state.selected() {
                    if let Some(lineage) = app.process_lineage_tuple_list.get(lineage_idx) {
                        if !lineage.is_empty() {
                            let i = state.process_list_state.selected().unwrap_or(0);
                            state.process_list_state.select(Some(i.saturating_sub(1)));
                        }
                    }
                }
            }
            KeyCode::Down => {
                if let Some(lineage_idx) = state.lineage_list_state.selected() {
                    if let Some(lineage) = app.process_lineage_tuple_list.get(lineage_idx) {
                        if !lineage.is_empty() {
                            let i = state.process_list_state.selected().unwrap_or(0);
                            if i < lineage.len() - 1 {
                                state.process_list_state.select(Some(i + 1));
                            }
                        }
                    }
                }
            }
            KeyCode::Left | KeyCode::BackTab => {
                state.active_panel = ActivePanel::Lineages;
            }
            KeyCode::Char(' ') => {
                if let Some(lineage_idx) = state.lineage_list_state.selected() {
                    if let Some(process_idx) = state.process_list_state.selected() {
                        if let Some(lineage) = app.process_lineage_tuple_list.get(lineage_idx) {
                            if let Some((path, hash)) = lineage.get(process_idx) {
                                // If remove returns None, it means the key was not in the map, so we insert it.
                                // Otherwise, it was in the map and has now been removed.
                                if app.toggled_paths.remove(path.as_str()).is_none() {
                                    app.toggled_paths.insert(path.clone(), hash.clone());
                                } 
                            }
                        }
                    }
                }
            }
            KeyCode::Enter => {
                let selected_paths: Vec<(String, String)> = app.toggled_paths.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                let debug_message = format!("[Permissive] Approved paths: {:?}", selected_paths);
                app.debug_print.add_message(debug_message);


                // Send new app ids message to firewhal-kernel
                let msg = FireWhalMessage::AddAppIds(firewhal_core::AppIdsToAdd {
                    component: "TUI".to_string(),
                    app_ids_to_add: selected_paths,
                });
                if let Some(zmq_sender) = &app.to_zmq_tx {
                    if let Err(e) = zmq_sender.try_send(msg) {
                        let _ = &app.debug_print.add_message(format!("Failed to send UpdateInterfaces message: {}", e));
                    } 
                } else { let _ = &app.debug_print.add_message("Interface Selection found no zmq sender".to_string()); }
            }
            _ => {}
        }
    }
}

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // --- Styles ---
    let highlight_style = Style::default().bg(Color::DarkGray);
    let active_panel_style = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title_style(Style::default().add_modifier(Modifier::BOLD));
    let inactive_panel_style = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Gray));

    // --- Panel 1: Lineages ---
    let lineage_items: Vec<ListItem> = app
        .process_lineage_tuple_list
        .iter()
        .map(|lineage| {
            // Create a summary string like "/bin/zsh -> /usr/bin/vim -> ..."
            let summary = lineage
                .iter()
                .map(|(path, _)| {
                    // Get just the filename
                    path.split('/')
                        .last()
                        .unwrap_or(path.as_str())
                        .to_string()
                })
                .collect::<Vec<String>>()
                .join(" -> ");
            ListItem::new(summary)
        })
        .collect();

    let lineage_list = List::new(lineage_items)
        .block(
            if app.permissive_mode_list_state.active_panel == ActivePanel::Lineages {
                active_panel_style.clone().title("Lineages (←→ to switch)")
            } else {
                inactive_panel_style.clone().title("Lineages")
            },
        )
        .highlight_style(highlight_style)
        .highlight_symbol(">> ");

    let mut lineage_list_state = app.permissive_mode_list_state.lineage_list_state.clone();
    f.render_stateful_widget(lineage_list, chunks[0], &mut lineage_list_state);

    // --- Panel 2: Processes ---
    let process_items: Vec<ListItem> = if let Some(selected_lineage_index) =
        lineage_list_state.selected()
    {
        if let Some(selected_lineage) = app.process_lineage_tuple_list.get(selected_lineage_index) {
            selected_lineage
                .iter()
                .map(|(path, hash)| {
                    let is_toggled = app.toggled_paths.contains(path);
                    let prefix = if is_toggled { "[x] " } else { "[ ] " };
                    let style = if is_toggled {
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let content = format!("{} (Hash: {}...)", path, &hash[..6.min(hash.len())]);
                    ListItem::new(Line::from(vec![Span::styled(prefix, style), Span::raw(content)]))
                })
                .collect()
        } else {
            vec![ListItem::new("Select a lineage to see processes.")]
        }
    } else {
        vec![ListItem::new("No lineages detected yet.")]
    };

    let process_list = List::new(process_items)
        .block(if app.permissive_mode_list_state.active_panel == ActivePanel::Processes {
            active_panel_style.title("Processes (Space to toggle, Enter to approve)")
        } else {
            inactive_panel_style.title("Processes")
        })
        .highlight_style(highlight_style)
        .highlight_symbol(">> ");

    let mut process_list_state = app.permissive_mode_list_state.process_list_state.clone();
    f.render_stateful_widget(process_list, chunks[1], &mut process_list_state);
}