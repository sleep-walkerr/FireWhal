/*
What should firewall rules include?
IP
MAC
PORT
APPLICATION - LATER

*/
use std::fs;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bincode::{config, Encode, Decode};
use pnet::datalink;


#[derive(Encode, Decode, Debug)]
pub enum Action {
    Allow,
    Deny
}

#[derive(Encode, Decode, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp
}


#[derive(Debug, Encode, Decode)]
pub struct Rule {
    pub action: Action,
    pub protocol: Protocol,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub description: String,
}

#[derive(Debug, Encode, Decode)]
pub struct FirewallConfig {
    pub rules: Vec<Rule>,
}

fn get_all_interfaces() -> Vec<String> {
    datalink::interfaces()
        .into_iter()
        .map(|iface| iface.name)
        .collect()
}


fn main() -> Result<(), Box<dyn Error>> {
    let my_rules = FirewallConfig {
        rules: vec![
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(443),
                description: "Allow outgoing HTTPS".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(443),
                description: "Allow outgoing HTTPS via UDP (for QUIC)".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(11371),
                description: "Pacman Port".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(11371),
                description: "Pacman Port".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(7777),
                description: "Wireguard".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(67),
                description: "Router communication".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(67),
                description: "Router communication".to_string(),
            },Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(22),
                description: "Outgoing SSH".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(123),
                description: "NTP for getting time".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(8443),
                description: "Https Alternate".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(5355),
                description: "LLMNR".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(636),
                description: "Lastpass".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(53),
                description: "Unencrypted DNS".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: None,
                dest_port: Some(853),
                description: "DNS-Over-TLS".to_string(),
            },
            Rule {
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(127,0,0,1))),
                dest_port: None,
                description: "Block a specific malicious IP".to_string(),
            },
            Rule {
                action: Action::Deny,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(7, 0, 0, 5))),
                dest_port: None,
                description: "Block a specific malicious IP".to_string(),
            },
            Rule {
                action: Action::Deny,
                protocol: Protocol::Tcp,
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 168, 8, 7))),
                dest_port: None,
                description: "Block a specific malicious IP".to_string(),
            },
            Rule {
                action: Action::Deny,
                protocol: Protocol::Icmp,
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(7, 0, 0, 5))),
                dest_port: None,
                description: "Block a specific malicious IP".to_string(),
            },
            Rule {
                action: Action::Deny,
                protocol: Protocol::Udp,
                source_ip: None,
                source_port: None,
                dest_ip: Some(IpAddr::V4(Ipv4Addr::new(172, 168, 8, 7))),
                dest_port: None,
                description: "Block a specific malicious IP".to_string(),
            },
        ],
    };

    


    let config = bincode::config::standard();
    let encoded_bytes: Vec<u8> = bincode::encode_to_vec(&my_rules, config)?;

    let file_path = "firewall.rules";
    fs::write(file_path, &encoded_bytes)?;
    println!("✅ Rules saved to {}", file_path);

    let data_from_file = fs::read(file_path)?;
    
    let (decoded_rules, len): (FirewallConfig, usize) =
        bincode::decode_from_slice(&data_from_file, config)?;

    println!("✅ Successfully loaded {} rules from file.", decoded_rules.rules.len());
    dbg!(decoded_rules);

    // Interface scan testing
    let interfaces = get_all_interfaces();
    println!("Available interfaces: {:?}", interfaces);

    Ok(())
}