use ratatui::{prelude::*, widgets::*};
use crossterm::event::{KeyCode, KeyModifiers};
use firewhal_core::{FireWhalMessage, ApplicationAllowlistConfig, AppIdentity, RequestToUpdateHashes};
use crate::ui::app::{App, HashState};
use crate::ui::centered_rect;
use std::path::PathBuf;
use std::str::FromStr;

/// Represents the current UI mode for the app management screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppManagementMode {
    /// The user is just viewing the list of apps.
    Viewing,
    /// The user is editing an app (or creating a new one).
    Editing(EditState),
    /// The user is being asked to confirm a deletion.
    ConfirmingDelete { selected_yes: bool },
}

/// Holds the state for the app editing form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    /// The index of the app being edited, or `None` if it's a new app.
    pub app_index: Option<usize>,
    /// The original name of the app, used to find it in the HashMap on save.
    pub original_name: String,
    /// The current name of the app being edited.
    pub name: String,
    /// The current state of the app's identity being edited.
    pub identity: AppIdentity,
    /// Which input field is currently focused.
    pub focused_field: FormField,
    /// The current text in the input buffer for the focused field.
    pub input_buffer: String,
}

/// The fields in our app editing form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormField {
    Name, Path, Hash, Save,
}

const FORM_FIELDS: [FormField; 4] = [FormField::Name, FormField::Path, FormField::Hash, FormField::Save];

/// Holds all state related to the app management screen.
#[derive(Debug, Clone)]
pub struct AppListState {
    pub table_state: TableState,
    pub mode: AppManagementMode,
}

impl Default for AppListState {
    fn default() -> Self {
        Self {
            table_state: TableState::default(),
            mode: AppManagementMode::Viewing,
        }
    }
}

pub fn handle_key_event(key_code: KeyCode, app: &mut App) {
    match app.app_list_state.mode { // This needs to be updated to handle modifiers
        AppManagementMode::Viewing => handle_viewing_keys(key_code, app),
        AppManagementMode::Editing(_) => handle_editing_keys(key_code, app),
        AppManagementMode::ConfirmingDelete { .. } => handle_confirm_delete_keys(key_code, app),
    }
}

fn handle_viewing_keys(key_code: KeyCode, app: &mut App) {
    match key_code {
        KeyCode::Down => { // This needs to be updated to handle modifiers
            let app_vec = get_sorted_apps(app);
            if !app_vec.is_empty() {
                let i = app.app_list_state.table_state.selected().unwrap_or(0);
                let next = if i >= app_vec.len() - 1 { 0 } else { i + 1 };
                app.app_list_state.table_state.select(Some(next));
            }
        }
        KeyCode::Up => { // This needs to be updated to handle modifiers
            let app_vec = get_sorted_apps(app);
            if !app_vec.is_empty() {
                let i = app.app_list_state.table_state.selected().unwrap_or(0);
                let prev = if i == 0 {
                    app_vec.len() - 1
                } else { i - 1 };
                app.app_list_state.table_state.select(Some(prev));
            }
        }
        KeyCode::Char('a') => {
            // Add new app
            let new_identity = AppIdentity {
                path: PathBuf::new(),
                hash: String::new(),
            };
            app.app_list_state.mode = AppManagementMode::Editing(EditState {
                app_index: None, // None signifies a new app
                original_name: String::new(),
                name: String::new(),
                identity: new_identity,
                focused_field: FormField::Name,
                input_buffer: String::new(),
            });
        }
        KeyCode::Char('e') => {
            // Edit selected app
            if let Some(selected_index) = app.app_list_state.table_state.selected() {
                let app_vec = get_sorted_apps(app);
                if let Some((name, identity)) = app_vec.get(selected_index).cloned() {
                    let focused_field = FormField::Name;
                    let input_buffer = name.clone(); // Start by editing the name
                    app.app_list_state.mode = AppManagementMode::Editing(EditState {
                        app_index: Some(selected_index),
                        original_name: name.clone(),
                        name,
                        identity,
                        focused_field,
                        input_buffer,
                    });
                }
            }
        }
        KeyCode::Char('d') => {
            // Delete selected app
            if app.app_list_state.table_state.selected().is_some() {
                app.app_list_state.mode = AppManagementMode::ConfirmingDelete {
                    selected_yes: false, // Default to "No"
                };
            }
        }
        KeyCode::Char('p') => {
            // Apply changes
            if app.apps_modified {
                send_apps_to_daemon(app);
                app.apps_modified = false;
            }
        }
        KeyCode::Char('h') => { // Re-hash selected application
            if let Some(selected_index) = app.app_list_state.table_state.selected() {
                let app_vec = get_sorted_apps(app);
                if let Some((name, identity)) = app_vec.get(selected_index) {
                    let mut app_to_rehash = std::collections::HashMap::new();
                    app_to_rehash.insert(name.clone(), identity.clone());

                    let msg = FireWhalMessage::HashUpdateRequest(RequestToUpdateHashes {
                        component: "TUI".to_string(),
                        apps_to_update_hash_for: app_to_rehash
                    });

                    if let Some(tx) = &app.to_zmq_tx {
                        if let Err(e) = tx.try_send(msg) {
                            app.debug_print.add_message(format!("[TUI] Failed to send single HashUpdateRequest: {}", e));
                        } else {
                            app.debug_print.add_message(format!("[TUI] Sent HashUpdateRequest for '{}'", name));
                            app.apps_modified = true; // Mark as modified
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

pub fn handle_key_event_with_modifiers(key_code: KeyCode, modifiers: KeyModifiers, app: &mut App) {
    if modifiers == KeyModifiers::CONTROL && key_code == KeyCode::Char('h') {
        // Re-hash all applications
        let all_apps_to_rehash = app.apps.clone();
        let msg = FireWhalMessage::HashUpdateRequest(RequestToUpdateHashes {
            component: "TUI".to_string(),
            apps_to_update_hash_for: all_apps_to_rehash,
        });

        if let Some(tx) = &app.to_zmq_tx {
            if let Err(e) = tx.try_send(msg) {
                app.debug_print.add_message(format!("[TUI] Failed to send bulk HashUpdateRequest: {}", e));
            } else {
                app.debug_print.add_message("[TUI] Sent HashUpdateRequest for all apps".to_string());
                app.apps_modified = true; // Mark as modified
            }
        }
    } else {
        // If no modifiers, or not the one we're looking for, pass to the normal handler
        handle_key_event(key_code, app);
    }
}

fn handle_editing_keys(key_code: KeyCode, app: &mut App) {
    if let AppManagementMode::Editing(state) = &mut app.app_list_state.mode {
        match key_code {
            KeyCode::Esc => {
                app.app_list_state.mode = AppManagementMode::Viewing;
            }
            KeyCode::Down => {
                apply_input_buffer(state);
                let current_index = FORM_FIELDS.iter().position(|&f| f == state.focused_field).unwrap_or(0);
                let next_index = (current_index + 1) % FORM_FIELDS.len();
                state.focused_field = FORM_FIELDS[next_index];
                state.input_buffer = field_to_string(&state.name, &state.identity, state.focused_field);
            }
            KeyCode::Up => {
                apply_input_buffer(state);
                let current_index = FORM_FIELDS.iter().position(|&f| f == state.focused_field).unwrap_or(0);
                let prev_index = (current_index + FORM_FIELDS.len() - 1) % FORM_FIELDS.len();
                state.focused_field = FORM_FIELDS[prev_index];
                state.input_buffer = field_to_string(&state.name, &state.identity, state.focused_field);
            }
            KeyCode::Enter if state.focused_field == FormField::Save => {
                apply_input_buffer(state);
                let new_name = state.name.clone();
                let new_identity = state.identity.clone();

                if state.app_index.is_some() {
                    // Editing existing app. Remove the old one if the name changed.
                    if state.original_name != new_name {
                        app.apps.remove(&state.original_name);
                    }
                    app.apps.insert(new_name, new_identity);
                } else {
                    // Adding new app
                    app.apps.insert(new_name, new_identity);
                }

                app.app_list_state.mode = AppManagementMode::Viewing;
                app.apps_modified = true;
            }
            KeyCode::Char(c) => {
                state.input_buffer.push(c);
            }
            KeyCode::Backspace => {
                state.input_buffer.pop();
            }
            _ => {}
        }
    }
}

fn apply_input_buffer(state: &mut EditState) {
    match state.focused_field {
        FormField::Name => state.name = state.input_buffer.clone(),
        FormField::Path => state.identity.path = PathBuf::from(&state.input_buffer),
        FormField::Hash => state.identity.hash = state.input_buffer.clone(),
        _ => {}
    }
}

fn field_to_string(name: &str, identity: &AppIdentity, field: FormField) -> String {
    match field {
        FormField::Name => name.to_string(),
        FormField::Path => identity.path.to_string_lossy().into_owned(),
        FormField::Hash => identity.hash.clone(),
        _ => String::new(),
    }
}

fn send_apps_to_daemon(app: &mut App) {
    let apps_hashmap = app.apps.clone();
    let config = ApplicationAllowlistConfig { apps: apps_hashmap };

    if let Some(tx) = &app.to_zmq_tx {
        // Use UpdateAppIds to send the complete, modified list to the daemon for saving.
        let msg = FireWhalMessage::UpdateAppIds(config);

        if let Err(e) = tx.try_send(msg) {
            app.debug_print.add_message(format!("[TUI] Failed to send app list to daemon: {}", e));
        } else {
            app.debug_print.add_message("[TUI] Sent updated app list to daemon.".to_string());
        }
    }
}

fn handle_confirm_delete_keys(key_code: KeyCode, app: &mut App) {
    if let AppManagementMode::ConfirmingDelete { selected_yes } = &mut app.app_list_state.mode {
        match key_code {
            KeyCode::Left | KeyCode::Right => {
                *selected_yes = !*selected_yes;
            }
            KeyCode::Enter => {
                if *selected_yes {
                    if let Some(selected_index) = app.app_list_state.table_state.selected() {
                        let app_vec = get_sorted_apps(app);
                        if let Some((name, _)) = app_vec.get(selected_index) {
                            // Remove from the HashMap using the name as the key
                            app.apps.remove(name);
                            app.apps_modified = true;
                        }
                    }
                    app.app_list_state.table_state.select(None); // Deselect
                }
                app.app_list_state.mode = AppManagementMode::Viewing;
            }
            KeyCode::Esc => {
                app.app_list_state.mode = AppManagementMode::Viewing;
            }
            _ => {}
        }
    }
}

/// Helper to get a sorted Vec from the app's HashMap for consistent display.
fn get_sorted_apps(app: &App) -> Vec<(String, AppIdentity)> {
    let mut app_vec: Vec<_> = app.apps.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    app_vec.sort_by(|a, b| a.0.cmp(&b.0));
    app_vec
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    render_apps_table(f, app, area);

    match &app.app_list_state.mode {
        AppManagementMode::Editing(state) => {
            let popup_area = centered_rect(80, 50, area);
            let form_block = Block::default()
                .title(if state.app_index.is_some() { "Edit App" } else { "Add App" })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(255, 165, 0)));

            let form_inner_area = form_block.inner(popup_area);
            f.render_widget(Clear, popup_area);
            f.render_widget(form_block, popup_area);

            let form_chunks = Layout::vertical([
                Constraint::Length(3), // Name
                Constraint::Length(3), // Path
                Constraint::Length(3), // Hash
                Constraint::Min(1),    // Spacer
                Constraint::Length(3), // Save Button
            ]).split(form_inner_area);

            let name_val = if state.focused_field == FormField::Name { &state.input_buffer } else { &state.name };
            render_form_field(f, form_chunks[0], "Name", name_val, state.focused_field == FormField::Name);

            let path_val = if state.focused_field == FormField::Path { &state.input_buffer } else { state.identity.path.to_str().unwrap_or("") };
            render_form_field(f, form_chunks[1], "Path", path_val, state.focused_field == FormField::Path);

            let hash_val = if state.focused_field == FormField::Hash { &state.input_buffer } else { &state.identity.hash };
            render_form_field(f, form_chunks[2], "Hash", hash_val, state.focused_field == FormField::Hash);


            let save_text = "Save App";
            let save_style = if state.focused_field == FormField::Save {
                Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black)
            } else {
                Style::default().fg(Color::Rgb(255, 165, 0))
            };
            let save_button = Paragraph::new(save_text).style(save_style).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL));
            f.render_widget(save_button, form_chunks[4]);
        }
        AppManagementMode::ConfirmingDelete { selected_yes } => {
            let popup_area = centered_rect(50, 25, area);
            let block = Block::default().title("Confirm Delete").borders(Borders::ALL);

            let text = vec![
                Line::from("Are you sure you want to delete this app?").alignment(Alignment::Center),
                Line::from(""),
                Line::from(vec![
                    Span::raw("      "),
                    Span::styled(" Yes ", if *selected_yes { Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black) } else { Style::default() }),
                    Span::raw("         "),
                    Span::styled(" No ", if !*selected_yes { Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black) } else { Style::default() }),
                ]).alignment(Alignment::Center),
            ];

            let paragraph = Paragraph::new(text).block(block);
            f.render_widget(Clear, popup_area);
            f.render_widget(paragraph, popup_area);
        }
        _ => {}
    }
}

fn render_form_field(f: &mut Frame, area: Rect, title: &str, value: &str, is_focused: bool) {
    let border_style = if is_focused { Style::default().fg(Color::Cyan) } else { Style::default().fg(Color::DarkGray) };
    let block = Block::default().title(title).borders(Borders::ALL).border_style(border_style);
    let inner_area = block.inner(area);

    let paragraph = Paragraph::new(value).block(Block::default());
    f.render_widget(block, area);
    f.render_widget(paragraph, inner_area);

    if is_focused {
        f.set_cursor_position(Position::new(inner_area.x + Span::raw(value).width() as u16, inner_area.y));
    }
}

fn render_apps_table(f: &mut Frame, app: &mut App, area: Rect) {
    let title = if app.apps_modified {
        "App Management* (a: add, e: edit, d: delete, h: re-hash, Ctrl+h: re-hash all, p: apply)"
    } else {
        "App Management (a: add, e: edit, d: delete, h: re-hash, Ctrl+h: re-hash all)"
    };

    let header = Row::new(["Name", "Path", "Hash"])
        .style(Style::default().fg(Color::Rgb(255, 165, 0)).bold())
        .height(1)
        .bottom_margin(1);

    let sorted_apps = get_sorted_apps(app);
    let rows = sorted_apps.iter().map(|(app_name, identity)| {
        let hash_style = match app.hash_states.get(app_name) {
            Some(HashState::Valid) => Style::default().fg(Color::Green),
            Some(HashState::Invalid) => Style::default().fg(Color::Red),
            _ => Style::default().fg(Color::White), // Default to white for Unchecked or if not found
        };
        let hash_cell = Cell::from(identity.hash.clone()).style(hash_style);

        Row::new(vec![
            Cell::from(app_name.clone()),
            Cell::from(identity.path.to_string_lossy().into_owned()),
            hash_cell,
        ]).height(1)
    });

    let widths = [Constraint::Percentage(20), Constraint::Percentage(50), Constraint::Percentage(30)];
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    f.render_stateful_widget(table, area, &mut app.app_list_state.table_state);
}
