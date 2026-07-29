//! Read-only monitoring library for the Anker SOLIX C1000 Gen 2 family
//! (PN A1763 / A1765 / AS100) portable power stations.
//!
//! Ported from the Python `anker-solix-api` project, scoped down to just
//! what's needed to log in, find the device, connect to Anker's cloud MQTT
//! broker, and decode its real-time `0421` status messages. No device
//! control commands, no energy-history polling, no Home Assistant layer --
//! see the project plan for the full rationale.

pub mod auth;
pub mod devices;
pub mod error;
pub mod mqtt;

pub use auth::AnkerSession;
pub use devices::{C1000_GEN2_PNS, Device, find_c1000_gen2, list_devices};
pub use error::{AnkerError, Result};
pub use mqtt::c1000gen2::C1000Gen2Status;
pub use mqtt::{MqttConnection, connect as mqtt_connect, publish_realtime_trigger, spawn_monitor};
