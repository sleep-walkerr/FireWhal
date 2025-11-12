// import UI screens
mod ui;
use ui::app::{App, AppScreen, HashState};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen, SetTitle},
};

use ratatui::{prelude::*, widgets::*, Terminal};
use std::{
    error::Error, f32::consts::E, io::{self,stdout}, ops::{self, RangeBounds, RangeTo}, sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    }, time::{Duration, Instant}
};

use tokio::{
    task::spawn_blocking,
    time::sleep,
    sync::{broadcast, mpsc},
};
use zmq;
use firewhal_core::{zmq_client_connection, FireWhalMessage, StatusUpdate, StatusPing};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::Mutex;

use crate::ui::app;

// Upon entering the interface selection menu, have the TUI send a message requesting the interface list
// The userspace loader receives the message, scans for interfaces, and then sends a request response
// The TUI then populates the list with the message it receives containing the available interfaces


#[tokio::main]
async fn main() -> Result<(), io::Error> {
    // Connect to IPC
    // `to_zmq_tx` is for the TUI to send messages TO the ZMQ task.
    // `from_zmq_rx` is for the TUI to receive messages FROM the ZMQ task.
    let (to_zmq_tx, to_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (from_zmq_tx, mut from_zmq_rx) = mpsc::channel::<FireWhalMessage>(32);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);


    // Spawn the ZMQ task.
    // `to_zmq_rx` is the `outgoing_rx` for the ZMQ task.
    // `from_zmq_tx` is the `incoming_tx` for the ZMQ task.
    let ipc_connection = tokio::spawn(zmq_client_connection(to_zmq_rx, from_zmq_tx, shutdown_rx, "TUI".to_string()));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, crossterm::cursor::Hide, SetTitle("FireWhal 🔥🐳"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?; // ⬅ clear screen before drawing

    // Main app variable needs multiple ownership, accomplished by Arc and Mutex
    // Arc allows for multiple owners for a piece of data, and mutex is used to lock usage to one owner at a time
    let app= Arc::new(Mutex::new(App::default())); 
    // Add sender channel to app to allow interfaces to send IPC messages
    app.lock().await.to_zmq_tx = Some(to_zmq_tx.clone());

    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    // Incoming Message Processing
    //--Clone reference to use in subroutine
    let app_clone  = Arc::clone(&app);

    // Craft Ident message
    let ident_message = FireWhalMessage::Status(StatusUpdate {
        component: "TUI".to_string(),
        is_healthy: true,
        message: "Ready".to_string(),
    }
    );
    
    // Send Ident Message
    match to_zmq_tx.send(ident_message).await {
        Ok(_) => {
            let mut app_guard = app_clone.lock().await;
            app_guard.debug_print.add_message("[TUI]: StatusUpdate Message Sent".to_string());
        },
        Err(e) => {
            let mut app_guard = app_clone.lock().await;
            app_guard.debug_print.add_message(format!("[TUI]: Failed to send StatusMessage with error {}", e));
        }
    }

    // Craft component ping 
    let ping_message = FireWhalMessage::Ping(StatusPing {
        source: "TUI".to_string(),
    });

    // Send component ping
    match to_zmq_tx.send(ping_message).await {
        Ok(_) => {
            let mut app_guard = app_clone.lock().await;
            app_guard.debug_print.add_message("[TUI]: StatusPing Message Sent".to_string());
        },
        Err(e) => {
            let mut app_guard = app_clone.lock().await;
            app_guard.debug_print.add_message(format!("[TUI]: Failed to send StatusPing with error {}", e));
        }
    }
    
    tokio::spawn(async move {
        while let Some(message) = from_zmq_rx.recv().await {
            let mut app_guard = app_clone.lock().await;
            match message {
                FireWhalMessage::Debug(msg) => {
                    let formatted_msg = format!("[{}]: {}", msg.source, msg.content);
                    app_guard.debug_print.add_message(formatted_msg);
                }
                FireWhalMessage::InterfaceResponse(response) => {
                    if response.source == "Daemon" {
                        // Clear vector entries
                        app_guard.available_interfaces.clear_interfaces();
                        // Add new entries
                        for interface in response.current_interfaces.iter() {app_guard.available_interfaces.add_interface(interface.to_string());}
                        for interface in response.interface_state.enforced_interfaces.iter() {app_guard.toggled_interfaces.insert(interface.to_string());}
                    }
                }
                FireWhalMessage::Pong(pong) => {   
                    app_guard.debug_print.add_message(format!("[{}]: Pong Received", pong.source));
                    match pong.source.as_str() {
                        "Daemon" => {
                            app_guard.main_menu.set_daemon_status(true)
                        }
                        "Firewall" => {
                            app_guard.main_menu.set_firewall_status(true)
                        }
                        "DiscordBot" => {
                            app_guard.main_menu.set_discord_bot_status(true)
                        }
                        "IPC" => {
                            app_guard.main_menu.set_ipc_status(true)
                        }
                        _ => {}
                    
                    }
                }
                FireWhalMessage::PermissiveModeTuple(tuple_message) =>
                {
                    if tuple_message.component == "Firewall" {
                        for lineage_tuple in tuple_message.lineage_tuple.clone() {
                            app_guard.debug_print.add_message(format!("[TUI]: Permissive Mode Tuple Received: [{}]", lineage_tuple.0));
                        }
                        app_guard.process_lineage_tuple_list.add_tuple(tuple_message.lineage_tuple.iter().cloned().collect());
                        // app_guard.debug_print.add_message("[TUI]: Permissive Mode Tuple Received".to_string());
                    }
                    
                }
                FireWhalMessage::RulesResponse(rules_message) => {
                    app_guard.debug_print.add_message(format!("[TUI]: RulesResponse Received."));
                    // Clear existing rules and add new ones
                    app_guard.rules.clear();
                    // For now, we only show outgoing rules. This can be expanded later.
                    app_guard.rules.extend(rules_message.outgoing_rules);
                    app_guard.rules.extend(rules_message.incoming_rules);
                }
                FireWhalMessage::AppsResponse(app_id_message) => {
                    app_guard.debug_print.add_message(format!("[TUI]: AppIdsResponse Received."));
                    // Clear existing apps and add new ones
                    app_guard.apps.clear();
                    // Also clear the hash states
                    app_guard.hash_states.clear();

                    app_guard.apps.extend(app_id_message.apps.into_iter());

                    // --- THE FIX: Send HashesRequest *after* receiving the app list ---
                    let apps_to_hash: std::collections::HashMap<String, firewhal_core::AppIdentity> = app_guard.apps.clone();
                    if !apps_to_hash.is_empty() {
                        // Set all hashes to unchecked initially
                        for name in apps_to_hash.keys() {
                            app_guard.hash_states.insert(name.clone(), HashState::Unchecked);
                        }

                        let hashes_request_msg = FireWhalMessage::HashesRequest(firewhal_core::TUIHashesRequest {
                            component: "TUI".to_string(),
                            apps_to_get_hashes_for: apps_to_hash,
                        });

                        if let Some(tx) = &app_guard.to_zmq_tx {
                            // Use try_send as we are in an async block but don't want to block it.
                            let _ = tx.try_send(hashes_request_msg);
                        }
                    }
                }
                FireWhalMessage::HashesResponse(message) => {
                    app_guard.debug_print.add_message(format!("[TUI]: HashesResponse Received."));
                    // Iterate through the original apps list to compare hashes
                    for (app_name, local_identity) in &app_guard.apps.clone() {
                        if let Some(app_identity) = message.apps_with_updated_hashes.get(app_name) {
                            let new_state = if local_identity.hash == app_identity.hash {
                                HashState::Valid
                            } else {
                                HashState::Invalid
                            };
                            app_guard.hash_states.insert(app_name.clone(), new_state);
                        }

                    }
                }
                FireWhalMessage::HashUpdateResponse(message) => {
                    app_guard.debug_print.add_message(format!("[TUI]: HashUpdateResponse Received."));
                    // Iterate through the original apps list to compare hashes
                    for (app_name, local_identity) in &app_guard.apps.clone() {
                        if let Some(app_identity) = message.updated_apps.get(app_name) {
                            let valid_state = HashState::Valid; // All applications are valid at this point
                            app_guard.hash_states.insert(app_name.clone(), valid_state);
                            app_guard.apps.insert(app_name.clone(), app_identity.clone());
                        }

                    }
                }
                _ => {}
            }
        }
    });

    loop {
        let mut app_guard = app.lock().await;

        terminal.draw(|f| ui::render(f, &mut app_guard))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed()).unwrap_or(Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Tab => {
                        app_guard.next_screen();
                        // THIS CODE CAUSES BUSY WAITING
                        // Match to correct interface and then perform relevant operations
                        match app_guard.screen {
                            AppScreen::InterfaceSelection => {
                                // Send a interface request message to firewhal-kernel if screen is interface selection
                                // Craft request message
                                let request_message = FireWhalMessage::InterfaceRequest(firewhal_core::NetInterfaceRequest {
                                    source: "TUI".to_string(),
                                });
                                // Send request message
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(request_message) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send InterfaceRequest message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Interface Selection found no zmq sender".to_string()); }
                            }
                            AppScreen::PermissiveMode => {
                                let enable_message = FireWhalMessage::EnablePermissiveMode(firewhal_core::PermissiveModeEnable { component: ("TUI".to_string()) });
                                // Send enable message to enable permissive mode
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(enable_message) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send EnablePermissiveMode message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Permissive Mode found no zmq sender".to_string()); }
                                //app_guard.process_lineage_tuple_list.clear_interfaces();
                            }
                            AppScreen::MainMenu => {
                                // Reset Status Values
                                app_guard.main_menu.reset_status_values();
                                // Send ping to components
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(FireWhalMessage::Ping(firewhal_core::StatusPing { source: "TUI".to_string() })) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send Ping message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Main Menu found no zmq sender".to_string()); }
                            }
                            AppScreen::RuleManagement => {
                                // FIX ME, permissive mode will have a toggle button in its interface, for now, just send the disable message when you swap to main
                                let disable_message = FireWhalMessage::DisablePermissiveMode(firewhal_core::PermissiveModeDisable { component: ("TUI".to_string()) });
                                // Send enable message to enable permissive mode
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(disable_message) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send EnablePermissiveMode message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Permissive Mode found no zmq sender".to_string()); }
                                // Send rule request to daemon
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(FireWhalMessage::RulesRequest(firewhal_core::TUIRulesRequest { component: "TUI".to_string() })) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send RuleRequest message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Found no zmq sender".to_string()); }
                            }
                            AppScreen::AppManagement => {
                                // Send app request to daemon
                                if let Some(zmq_sender) = &app_guard.to_zmq_tx {
                                    if let Err(e) = zmq_sender.try_send(FireWhalMessage::AppsRequest(firewhal_core::TUIAppsRequest { component: "TUI".to_string() })) {
                                        _ = &app_guard.debug_print.add_message(format!("Failed to send RuleRequest message: {}", e));
                                    }
                                } else { _ = &app_guard.debug_print.add_message("Found no zmq sender".to_string()); }
                                // The HashesRequest is now sent automatically after AppsResponse is received.
                            }
                            _ => { 
                            }
                        }
                    },
                    _ => { // For other keys used in specific interfaces
                        match app_guard.screen {
                                    AppScreen::InterfaceSelection => {
                                        ui::interface_selection::handle_key_event(key.code, &mut app_guard);
                                    },
                                    AppScreen::PermissiveMode => {
                                        ui::permissive_mode::handle_key_event(key.code, &mut app_guard);
                                    },
                                    AppScreen::RuleManagement => {
                                        ui::rule_management::handle_key_event(key.code, &mut app_guard);
                                    }
                                    AppScreen::AppManagement => {
                                        ui::app_management::handle_key_event_with_modifiers(key.code, key.modifiers, &mut app_guard);
                                    }
                                    AppScreen::MainMenu => {
                                    },
                                    _ => {}
                                }
                    }
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            // Delegate updates to the active screen's state
            match app_guard.screen {
                AppScreen::MainMenu => app_guard.main_menu.update_progress(),
                _ => { /* Other screens might have their own updates here */ }
            }
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, crossterm::cursor::Show)?;
    terminal.show_cursor()?; // optional: make sure cursor reappears

    // 3. Send the shutdown signal
    println!("TUI exited. Shutting down ZMQ task...");
    shutdown_tx.send(()).unwrap();
    drop(to_zmq_tx); // This will cause the zmq_client_connection to exit its loop.

    //NOT WAITING ON THIS MEANS THAT THE ZMQ FUNCTION IS BEING FORCEFULLY SHUTDOWN
    //This is happening everywhere and needs to be fixed
    // 4. Wait for the ZMQ task to finish cleanly
    if let Err(e) = ipc_connection.await {
        eprintln!("ZMQ task did not shut down cleanly: {:?}", e);
    }

    Ok(())
}