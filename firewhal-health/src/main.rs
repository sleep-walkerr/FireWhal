//! firewhal-health — boot-time config validator (C1, design doc §2.4).
//!
//! Validates the three FireWhal config tomls with the *same* parse the
//! daemon uses (shared loaders in `firewhal-core`), so the validator can
//! never disagree with the daemon about what is valid.
//!
//! Exit codes:
//!   0 — all three files present and valid
//!   1 — one or more files missing/malformed (the `firewhal-health`
//!       oneshot unit shows **failed** — never green on a broken config,
//!       the UFW `ufw.service` loudness)
//!
//! The output states what is wrong *and which fail-closed posture is in
//! effect* (e.g. "defaulting to all non-loopback interfaces — fail-closed,
//! not as configured"), because a missing config file is not fatal: the
//! daemon stays up in the fail-closed posture and announces the degraded
//! state (alarm bundle + TUI).
//!
//! Usage: firewhal-health [config-dir]   (default: /opt/firewhal/bin)

use std::path::Path;
use std::process::ExitCode;

use firewhal_core::{
    ConfigLoadResult, load_app_ids_config, load_interface_state_config, load_rules_config,
};

fn main() -> ExitCode {
    let config_dir: std::path::PathBuf = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new("/opt/firewhal/bin").to_path_buf());

    println!("firewhal-health: validating config in {}", config_dir.display());

    let rules = config_dir.join("firewall_rules.toml");
    let apps = config_dir.join("app_identity.toml");
    let ifaces = config_dir.join("interface_state.toml");

    let mut degraded = 0usize;

    // --- firewall_rules.toml: missing/malformed -> empty rule set,
    //     default-deny (all traffic blocked — fail-closed) ---
    match load_rules_config(&rules) {
        ConfigLoadResult::Loaded(_) => println!("  OK        firewall_rules.toml"),
        ConfigLoadResult::Missing => {
            degraded += 1;
            println!("  DEGRADED  firewall_rules.toml: missing — NO RULES will be loaded; all traffic blocked (fail-closed default). Restore the file.");
        }
        ConfigLoadResult::Malformed { reason } => {
            degraded += 1;
            println!("  DEGRADED  firewall_rules.toml: malformed ({reason}) — NO RULES will be loaded; all traffic blocked (fail-closed default). Fix the file.");
        }
    }

    // --- app_identity.toml: missing -> daemon bootstraps an empty
    //     allowlist (egress denied at the app gate — fail-closed);
    //     malformed -> empty allowlist (same posture) ---
    match load_app_ids_config(&apps) {
        ConfigLoadResult::Loaded(c) if !c.apps.is_empty() => {
            println!("  OK        app_identity.toml ({} app(s))", c.apps.len());
        }
        ConfigLoadResult::Loaded(_) => {
            degraded += 1;
            println!("  DEGRADED  app_identity.toml: valid but EMPTY — all egress denied at the app gate (fail-closed). Restore the allowlist.");
        }
        ConfigLoadResult::Missing => {
            degraded += 1;
            println!("  DEGRADED  app_identity.toml: missing — daemon will bootstrap an empty allowlist; all egress denied (fail-closed). Restore the file.");
        }
        ConfigLoadResult::Malformed { reason } => {
            degraded += 1;
            println!("  DEGRADED  app_identity.toml: malformed ({reason}) — an empty allowlist is in effect; all egress denied (fail-closed). Fix the file.");
        }
    }

    // --- interface_state.toml: missing/malformed/empty -> the daemon
    //     defaults to ALL non-loopback interfaces (fail-closed; enforcement
    //     is never left unattached) ---
    match load_interface_state_config(&ifaces) {
        ConfigLoadResult::Loaded(c) if !c.enforced_interfaces.is_empty() => {
            println!(
                "  OK        interface_state.toml ({} enforced interface(s))",
                c.enforced_interfaces.len()
            );
        }
        ConfigLoadResult::Loaded(_) => {
            degraded += 1;
            println!("  DEGRADED  interface_state.toml: valid but EMPTY — daemon will default to all non-loopback interfaces (fail-closed, not as configured). Restore the file.");
        }
        ConfigLoadResult::Missing => {
            degraded += 1;
            println!("  DEGRADED  interface_state.toml: missing — daemon will default to all non-loopback interfaces (fail-closed, not as configured; your management path is protected only if your rules allow it). Restore the file.");
        }
        ConfigLoadResult::Malformed { reason } => {
            degraded += 1;
            println!("  DEGRADED  interface_state.toml: malformed ({reason}) — daemon will default to all non-loopback interfaces (fail-closed, not as configured). Fix the file.");
        }
    }

    if degraded == 0 {
        println!("firewhal-health: all config files valid.");
        ExitCode::SUCCESS
    } else {
        println!("firewhal-health: {degraded} degraded file(s) — safe (fail-closed) but not as configured; see the lines above and /var/log/firewhal/config-alert.log.");
        ExitCode::from(1)
    }
}
