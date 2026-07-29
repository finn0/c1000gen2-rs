//! Toy demo CLI: poll real-time status of a SOLIX C1000 Gen 2 via the
//! `c1000gen2_rs` lib. Rust equivalent of
//! `anker-solix-api/toy/c1000_gen2_status.py`.
//!
//! Credentials come from a `.env` file (ANKERUSER / ANKERPASSWORD /
//! ANKERCOUNTRY) or interactive prompts, same as the Python demo.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use c1000gen2_rs::{AnkerSession, C1000Gen2Status, find_c1000_gen2, list_devices, mqtt_connect, spawn_monitor};
use tokio::sync::RwLock;

const POLL_INTERVAL_SECS: u64 = 3;
const TRIGGER_TIMEOUT_SECS: u32 = 300;

fn env_or_prompt(var: &str, label: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| {
        print!("{label}: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();

        line.trim().to_string()
    })
}

#[tokio::main]
async fn main() -> c1000gen2_rs::Result<()> {
    // 1. loads *.env* file from pwd.
    dotenvy::dotenv().ok();

    let email = env_or_prompt("ANKERUSER", "Username (email)");
    let password = env_or_prompt("ANKERPASSWORD", "Password");
    let country = env_or_prompt("ANKERCOUNTRY", "Country ID (e.g. US)");

    // 2. login
    let session = AnkerSession::new(email, password, country)?;
    session.login(false).await?;

    // 3. load devices
    println!("Loading devices...");

    let devices = list_devices(&session).await?;

    println!("Devices in your account:");
    for d in &devices {
        println!("  sn={} pn={} name={}", d.device_sn, d.device_pn, d.device_name);
    }

    let Some(device) = find_c1000_gen2(&devices).cloned() else {
        eprintln!("No C1000 Gen 2 device found in your account.");
        return Ok(());
    };
    println!("Found device {} ({})", device.device_sn, device.device_pn);

    let conn = mqtt_connect(&session).await?;
    println!("Connected to MQTT server {}:8883", conn.info.endpoint_addr);

    let status = Arc::new(RwLock::new(C1000Gen2Status::default()));
    let _monitor = spawn_monitor(conn, device, TRIGGER_TIMEOUT_SECS, status.clone());

    println!("Polling every {POLL_INTERVAL_SECS} seconds, press Ctrl+C to stop...");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)) => {
                let s = status.read().await;
                println!("{}", s.format_full());
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Stopping...");
                break;
            }
        }
    }

    Ok(())
}
