use ratatui::{prelude::*, widgets::*, widgets::block::Title};
use crossterm::event::{KeyCode, KeyEvent};
use firewhal_core::{FireWhalConfig, FireWhalMessage, Rule, Action, Protocol};
use crate::ui::app::App;
use crate::ui::centered_rect;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

/// Represents the current UI mode for the rule management screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleManagementMode {
    /// The user is just viewing the list of rules.
    Viewing,
    /// The user is editing a rule (or creating a new one).
    Editing(EditState),
    /// The user is being asked to confirm a deletion.
    ConfirmingDelete { selected_yes: bool },
}

/// Holds the state for the rule editing form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditState {
    /// The index of the rule being edited, or `None` if it's a new rule.
    pub rule_index: Option<usize>,
    /// The current state of the rule being edited.
    pub rule: Rule,
    /// Which input field is currently focused.
    pub focused_field: FormField,
    /// The current text in the input buffer for the focused field.
    pub input_buffer: String,
}

/// The fields in our rule editing form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormField {
    Action, Protocol, SourceIp, SourcePort, DestIp, DestPort, Description, Save,
}

const FORM_FIELDS: [FormField; 8] = [FormField::Action, FormField::Protocol, FormField::SourceIp, FormField::SourcePort, FormField::DestIp, FormField::DestPort, FormField::Description, FormField::Save];


/// Holds all state related to the rule management screen.
#[derive(Debug, Clone)]
pub struct RuleListState {
    pub list_state: ListState,
    pub mode: RuleManagementMode,
}

impl Default for RuleListState {
    fn default() -> Self {
        Self {
            list_state: ListState::default(),
            mode: RuleManagementMode::Viewing,
        }
    }
}

pub fn handle_key_event(key_code: KeyCode, app: &mut App) {


    match app.rule_list_state.mode {
        RuleManagementMode::Viewing => handle_viewing_keys(key_code, app),
        RuleManagementMode::Editing(_) => handle_editing_keys(key_code, app),
        RuleManagementMode::ConfirmingDelete { .. } => handle_confirm_delete_keys(key_code, app),
    }
}

fn handle_viewing_keys(key_code: KeyCode, app: &mut App) {
    match key_code {
        KeyCode::Down => {
            if !app.rules.is_empty() {
                let i = app.rule_list_state.list_state.selected().unwrap_or(0);
                let next = if i >= app.rules.len() - 1 { 0 } else { i + 1 };
                app.rule_list_state.list_state.select(Some(next));
            }
        }
        KeyCode::Up => {
            if !app.rules.is_empty() {
                let i = app.rule_list_state.list_state.selected().unwrap_or(0);
                let prev = if i == 0 { app.rules.len() - 1 } else { i - 1 };
                app.rule_list_state.list_state.select(Some(prev));
            }
        }
        KeyCode::Char('a') => {
            // Add new rule
            let new_rule = Rule {
                action: Action::Allow,
                protocol: None,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: None,
                app_id: None,
                description: String::new(),
            };
            app.rule_list_state.mode = RuleManagementMode::Editing(EditState {
                rule_index: None, // None signifies a new rule
                rule: new_rule,
                focused_field: FormField::Action,
                input_buffer: String::new(),
            });
        }
        KeyCode::Char('e') => {
            // Edit selected rule
            if let Some(selected_index) = app.rule_list_state.list_state.selected() {
                if let Some(rule_to_edit) = app.rules.get(selected_index).cloned() {
                    let focused_field = FormField::Action;
                    let input_buffer = field_to_string(&rule_to_edit, focused_field);
                    app.rule_list_state.mode = RuleManagementMode::Editing(EditState {
                        rule_index: Some(selected_index),
                        rule: rule_to_edit,
                        focused_field,
                        input_buffer,
                    });
                }
            }
        }
        KeyCode::Char('d') => {
            // Delete selected rule
            if app.rule_list_state.list_state.selected().is_some() {
                app.rule_list_state.mode = RuleManagementMode::ConfirmingDelete {
                    selected_yes: false, // Default to "No"
                };
            }
        }
        KeyCode::Char('p') => {
            // Apply changes
            if app.rules_modified {
                send_rules_to_daemon(app);
                app.rules_modified = false;
            }
        }
        _ => {}
    }
}

fn handle_editing_keys(key_code: KeyCode, app: &mut App) {
    if let RuleManagementMode::Editing(state) = &mut app.rule_list_state.mode {
        match key_code {
            KeyCode::Esc => { // This should work regardless of the focused field
                app.rule_list_state.mode = RuleManagementMode::Viewing;
            }
            // --- Form Navigation ---
            KeyCode::Down => { // This should work regardless of the focused field
                apply_input_buffer(state); // Apply changes before switching
                let current_index = FORM_FIELDS.iter().position(|&f| f == state.focused_field).unwrap_or(0);
                let next_index = (current_index + 1) % FORM_FIELDS.len();
                state.focused_field = FORM_FIELDS[next_index];
                state.input_buffer = field_to_string(&state.rule, state.focused_field);
            }
            KeyCode::Up => { // This should work regardless of the focused field
                apply_input_buffer(state); // Apply changes before switching
                let current_index = FORM_FIELDS.iter().position(|&f| f == state.focused_field).unwrap_or(0);
                let prev_index = (current_index + FORM_FIELDS.len() - 1) % FORM_FIELDS.len();
                state.focused_field = FORM_FIELDS[prev_index];
                state.input_buffer = field_to_string(&state.rule, state.focused_field);
            }
            
            // --- Field-specific handling ---
            KeyCode::Enter if state.focused_field == FormField::Save => { // Only when Save is focused
                apply_input_buffer(state); // Apply any pending changes
                let new_rule = state.rule.clone();
                if let Some(index) = state.rule_index {
                    // Editing existing rule
                    app.rules[index] = new_rule;
                } else {
                    // Adding new rule
                    app.rules.push(new_rule);
                }
                app.rule_list_state.mode = RuleManagementMode::Viewing;
                app.rules_modified = true;
            }

            // -- Toggle Fields --
            KeyCode::Left | KeyCode::Right if state.focused_field == FormField::Action => { // Only when Action is focused
                state.rule.action = match state.rule.action {
                    Action::Allow => Action::Deny,
                    Action::Deny => Action::Allow,
                };
            }
            KeyCode::Left | KeyCode::Right if state.focused_field == FormField::Protocol => { // Only when Protocol is focused
                state.rule.protocol = match state.rule.protocol {
                    None => Some(Protocol::Tcp),
                    Some(Protocol::Tcp) => Some(Protocol::Udp),
                    Some(Protocol::Udp) => Some(Protocol::Icmp),
                    Some(Protocol::Icmp) => None,
                    // This handles the case where the protocol from core might be something else, like Wildcard
                    _ => Some(Protocol::Tcp),
                };
            }

            // -- Text Input Fields --
            // These should only work on text input fields
            _ => match state.focused_field {
                FormField::SourceIp | FormField::SourcePort | FormField::DestIp | FormField::DestPort | FormField::Description => {
                    if let KeyCode::Char(c) = key_code {
                        state.input_buffer.push(c);
                    } else if let KeyCode::Backspace = key_code {
                        state.input_buffer.pop();
                    }
                }
                _ => {} // Do nothing for other fields
            }
        }
    }
}

/// When moving away from a text field, parse the input buffer and update the rule state.
fn apply_input_buffer(state: &mut EditState) {
    match state.focused_field {
        FormField::SourceIp => {
            state.rule.source_ip = IpAddr::from_str(&state.input_buffer).ok();
        }
        FormField::SourcePort => {
            state.rule.source_port = state.input_buffer.parse::<u16>().ok();
        }
        FormField::DestIp => {
            state.rule.dest_ip = IpAddr::from_str(&state.input_buffer).ok();
        }
        FormField::DestPort => {
            state.rule.dest_port = state.input_buffer.parse::<u16>().ok();
        }
        FormField::Description => {
            state.rule.description = state.input_buffer.clone();
        }
        _ => {} // Not a text field
    }
}

/// When moving to a new field, get its current value as a string for the input buffer.
fn field_to_string(rule: &Rule, field: FormField) -> String {
    match field {
        FormField::SourceIp => rule.source_ip.map_or(String::new(), |ip| ip.to_string()),
        FormField::SourcePort => rule.source_port.map_or(String::new(), |p| p.to_string()),
        FormField::DestIp => rule.dest_ip.map_or(String::new(), |ip| ip.to_string()),
        FormField::DestPort => rule.dest_port.map_or(String::new(), |p| p.to_string()),
        FormField::Description => rule.description.clone(),
        _ => String::new(), // Not a text field
    }
}

/// Sends the complete, current list of rules to the daemon.
fn send_rules_to_daemon(app: &mut App) {
    let config = FireWhalConfig {
        // For now, we'll just put all rules in outgoing. This can be refined later.
        outgoing_rules: app.rules.clone(),
        incoming_rules: vec![],
    };
    if let Some(tx) = &app.to_zmq_tx {
        if let Err(e) = tx.try_send(FireWhalMessage::UpdateRules(config)) {
            app.debug_print.add_message(format!("[TUI] Failed to send rules to daemon: {}", e));
        } else {
            app.debug_print.add_message("[TUI] Sent rules to daemon.".to_string());
        }
    }
}

fn handle_confirm_delete_keys(key_code: KeyCode, app: &mut App) {
    if let RuleManagementMode::ConfirmingDelete { selected_yes } = &mut app.rule_list_state.mode {
        match key_code {
            KeyCode::Left | KeyCode::Right => {
                *selected_yes = !*selected_yes;
            }
            KeyCode::Enter => {
                if *selected_yes {
                    if let Some(selected_index) = app.rule_list_state.list_state.selected() {
                        if selected_index < app.rules.len() {
                            app.rules.remove(selected_index);
                            app.rules_modified = true;
                        }
                    }
                    app.rule_list_state.list_state.select(None); // Deselect
                }
                app.rule_list_state.mode = RuleManagementMode::Viewing;
            }
            KeyCode::Esc => {
                app.rule_list_state.mode = RuleManagementMode::Viewing;
            }
            _ => {}
        }
    }
}

pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    
    // Base table
    render_rules_table(f, app, area);

    // Render modals on top if necessary
    match &app.rule_list_state.mode {
        RuleManagementMode::Editing(state) => {
            let popup_area = centered_rect(80, 70, area);
            let form_block = Block::default()
                .title(if state.rule_index.is_some() { "Edit Rule" } else { "Add Rule" })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(255, 165, 0)));

            let form_inner_area = form_block.inner(popup_area);
            f.render_widget(Clear, popup_area); // this clears the background
            f.render_widget(form_block, popup_area);

            let form_chunks = Layout::vertical([
                Constraint::Length(3), // Action
                Constraint::Length(3), // Protocol
                Constraint::Length(3), // Source IP
                Constraint::Length(3), // Source Port
                Constraint::Length(3), // Dest IP
                Constraint::Length(3), // Dest Port
                Constraint::Length(3), // Description
                Constraint::Min(1),    // Spacer
                Constraint::Length(3), // Save Button
            ]).split(form_inner_area);

            // Render each field
            render_form_field(f, form_chunks[0], "Action", &format!("{:?}", state.rule.action), state.focused_field == FormField::Action, false, None);
            render_form_field(f, form_chunks[1], "Protocol", &state.rule.protocol.map_or("any".to_string(), |p| format!("{:?}", p)), state.focused_field == FormField::Protocol, false, None);
            
            let src_ip_val = if state.focused_field == FormField::SourceIp { &state.input_buffer } else { &field_to_string(&state.rule, FormField::SourceIp) };
            render_form_field(f, form_chunks[2], "Source IP", src_ip_val, state.focused_field == FormField::SourceIp, true, Some(form_chunks[2]));

            let src_port_val = if state.focused_field == FormField::SourcePort { &state.input_buffer } else { &field_to_string(&state.rule, FormField::SourcePort) };
            render_form_field(f, form_chunks[3], "Source Port", src_port_val, state.focused_field == FormField::SourcePort, true, Some(form_chunks[3]));

            let dest_ip_val = if state.focused_field == FormField::DestIp { &state.input_buffer } else { &field_to_string(&state.rule, FormField::DestIp) };
            render_form_field(f, form_chunks[4], "Dest IP", dest_ip_val, state.focused_field == FormField::DestIp, true, Some(form_chunks[4]));

            let dest_port_val = if state.focused_field == FormField::DestPort { &state.input_buffer } else { &field_to_string(&state.rule, FormField::DestPort) };
            render_form_field(f, form_chunks[5], "Dest Port", dest_port_val, state.focused_field == FormField::DestPort, true, Some(form_chunks[5]));

            let desc_val = if state.focused_field == FormField::Description { &state.input_buffer } else { &field_to_string(&state.rule, FormField::Description) };
            render_form_field(f, form_chunks[6], "Description", desc_val, state.focused_field == FormField::Description, true, Some(form_chunks[6]));

            // Save Button
            let save_text = "Save Rule";
            let save_style = if state.focused_field == FormField::Save {
                Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black)
            } else {
                Style::default().fg(Color::Rgb(255, 165, 0))
            };
            let save_button = Paragraph::new(save_text).style(save_style).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL));
            f.render_widget(save_button, form_chunks[8]);
        }
        RuleManagementMode::ConfirmingDelete { selected_yes } => {
            let popup_area = centered_rect(50, 25, area);
            let block = Block::default().title("Confirm Delete").borders(Borders::ALL);

            let question = "Are you sure you want to delete this rule?";
            let yes_style = if *selected_yes { Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black) } else { Style::default() };
            let no_style = if !*selected_yes { Style::default().bg(Color::Rgb(255, 165, 0)).fg(Color::Black) } else { Style::default() };

            let text = vec![
                Line::from(""),
                Line::from(question).alignment(Alignment::Center),
                Line::from(""),
                Line::from(vec![
                    Span::raw("      "),
                    Span::styled(" Yes ", yes_style),
                    Span::raw("         "),
                    Span::styled(" No ", no_style),
                ]).alignment(Alignment::Center),
                Line::from(""),
                Line::from("(Use ←/→ and Enter to confirm)").alignment(Alignment::Center).fg(Color::DarkGray),
            ];

            let paragraph = Paragraph::new(text)
                .block(block);

            f.render_widget(Clear, popup_area);
            f.render_widget(paragraph, popup_area);
        }
        RuleManagementMode::Viewing => {
            // Do nothing extra
        }
    }
}

fn render_form_field(f: &mut Frame, area: Rect, title: &str, value: &str, is_focused: bool, is_input: bool, cursor_area: Option<Rect>) {
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default().title(title).borders(Borders::ALL).border_style(border_style);
    let inner_area = block.inner(area);

    let text = if is_input && is_focused {
        value
    } else if is_input { // For non-focused input fields
        value
    } else { // For non-input (toggle) fields
        &format!("< {} >", value)
    };

    let paragraph = Paragraph::new(text).block(Block::default());
    f.render_widget(block, area);
    f.render_widget(paragraph, inner_area);

    if is_focused && is_input {
        f.set_cursor_position(Position::new(inner_area.x + Span::raw(value).width() as u16, inner_area.y));
    }
}

fn render_rules_table(f: &mut Frame, app: &mut App, area: Rect) {
    // Define column widths
    let widths = [
        Constraint::Percentage(8),  // Action
        Constraint::Percentage(8),  // Protocol
        Constraint::Percentage(15), // Src IP
        Constraint::Percentage(8),  // Src Port
        Constraint::Percentage(15), // Dest IP
        Constraint::Percentage(8),  // Dest Port
        Constraint::Percentage(38), // Description
    ];
    let layout = Layout::horizontal(widths);

    let modified_indicator = if app.rules_modified { "*" } else { "" };
    let title_spans = Line::from(vec![
        Span::raw("Rule Management"),
        Span::styled(modified_indicator, Style::default().fg(Color::Yellow)),
        Span::raw(" ("),
        Span::styled("a", Style::default().fg(Color::Rgb(255, 165, 0))),
        Span::raw(": add, "),
        Span::styled("e", Style::default().fg(Color::Rgb(255, 165, 0))),
        Span::raw(": edit, "),
        Span::styled("d", Style::default().fg(Color::Rgb(255, 165, 0))),
        Span::raw(": delete"),
        if app.rules_modified { Span::styled(", p: apply", Style::default().fg(Color::Rgb(255, 165, 0))) } else { Span::raw("") },
        Span::raw(")"),
    ]);
    let title = Title::from(title_spans).content.style(Style::default().fg(Color::Blue));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Blue))
        .title(title);
    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let list_layout = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(inner_area);
    let header_area = list_layout[0];
    let list_area = list_layout[1];

    // Render Header
    let header_spans = ["Action", "Protocol", "Src IP", "Src Port", "Dest IP", "Dest Port", "Description"];
    let header_cols = layout.split(header_area);
    for (i, header) in header_spans.iter().enumerate() {
        f.render_widget(Paragraph::new(*header).style(Style::default().fg(Color::Rgb(255, 165, 0)).bold()), header_cols[i]);
    }

    // Render List Items
    let list_item_cols = layout.split(Rect::new(0, 0, inner_area.width, 1)); // Create a template rect to get widths
    let items: Vec<ListItem> = app.rules.iter().map(|rule| {
        let col_widths: Vec<usize> = list_item_cols.iter().map(|r| r.width as usize).collect();

        let action = format!("{:<width$}", format!("{:?}", rule.action), width = col_widths[0]);
        let protocol = format!("{:<width$}", rule.protocol.map_or("any".to_string(), |p| format!("{:?}", p)), width = col_widths[1]);
        let src_ip = format!("{:<width$}", rule.source_ip.map_or("any".to_string(), |ip| ip.to_string()), width = col_widths[2]);
        let src_port = format!("{:<width$}", rule.source_port.map_or("any".to_string(), |p| p.to_string()), width = col_widths[3]);
        let dest_ip = format!("{:<width$}", rule.dest_ip.map_or("any".to_string(), |ip| ip.to_string()), width = col_widths[4]);
        let dest_port = format!("{:<width$}", rule.dest_port.map_or("any".to_string(), |p| p.to_string()), width = col_widths[5]);
        let desc = format!("{:<width$}", rule.description.clone(), width = col_widths[6]);

        let cells = vec![action, protocol, src_ip, src_port, dest_ip, dest_port, desc];
        let combined_string = cells.join("");
        // The content MUST be truncated to the inner width minus the two border characters.
        let content_width = inner_area.width.saturating_sub(2) as usize;
        let truncated_string = combined_string.chars().take(content_width).collect::<String>();

        let item_width = inner_area.width as usize;
        let bar_width = item_width.saturating_sub(2);
        let top_border = format!("╭{}╮", "─".repeat(bar_width));
        let bottom_border = format!("╰{}╯", "─".repeat(bar_width));

        let mut content_spans = vec![Span::raw("│")];
        content_spans.push(Span::raw(format!("{:<width$}", truncated_string, width = content_width)));
        content_spans.push(Span::raw("│"));
        let content_line = Line::from(content_spans);

        let lines = vec![
            Line::from(top_border),
            content_line,
            Line::from(bottom_border),
        ];
        ListItem::new(lines)
    }).collect();

    let list = List::new(items)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(list, list_area, &mut app.rule_list_state.list_state);
}
