//! Anker Solix cloud MQTT connection (read-only monitoring).
//!
//! Ported from `anker-solix-api/src/anker_solix_api/mqtt.py` and
//! `session.py:get_mqtt_info`. Authentication to the broker is mutual TLS
//! (AWS IoT Core style client-cert auth), not username/password -- the
//! client cert/key/CA are fetched via a REST call and passed to rumqttc as
//! in-memory PEM byte buffers (no temp files needed, unlike the Python
//! implementation which writes them to disk for paho-mqtt's file-path-based
//! `tls_set`).

pub mod c1000gen2;
pub mod codec;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rumqttc::{AsyncClient, Event, EventLoop, MqttOptions, Packet, QoS, Transport};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::auth::AnkerSession;
use crate::devices::Device;
use crate::error::{AnkerError, Result};
use c1000gen2::C1000Gen2Status;

const GET_MQTT_INFO_ENDPOINT: &str = "app/devicemanage/get_user_mqtt_info";

#[derive(Debug, Clone, Deserialize)]
pub struct MqttInfo {
    pub user_id: String,
    pub app_name: String,
    pub thing_name: String,
    pub certificate_id: String,
    pub certificate_pem: String,
    pub private_key: String,
    pub aws_root_ca1_pem: String,
    pub endpoint_addr: String,
}

async fn get_mqtt_info(session: &AnkerSession) -> Result<MqttInfo> {
    let data = session.post_json(GET_MQTT_INFO_ENDPOINT, json!({})).await?;
    serde_json::from_value(data).map_err(AnkerError::from)
}

fn topic_prefix(app_name: &str, pn: &str, sn: &str, publish: bool) -> String {
    format!("{}/{app_name}/{pn}/{sn}/", if publish { "cmd" } else { "dt" })
}

pub struct MqttConnection {
    pub client: AsyncClient,
    pub eventloop: EventLoop,
    pub info: MqttInfo,
}

/// Connect to the Anker cloud MQTT broker for the account owning `session`.
pub async fn connect(session: &AnkerSession) -> Result<MqttConnection> {
    let info = get_mqtt_info(session).await?;
    let client_id = format!("{}_{:05}", info.thing_name, rand::random::<u32>() % 100_000);
    let mut opts = MqttOptions::new(client_id, info.endpoint_addr.clone(), 8883);
    opts.set_keep_alive(Duration::from_secs(60));
    opts.set_clean_session(true);
    opts.set_transport(Transport::tls(
        info.aws_root_ca1_pem.clone().into_bytes(),
        Some((
            info.certificate_pem.clone().into_bytes(),
            info.private_key.clone().into_bytes(),
        )),
        None,
    ));
    let (client, eventloop) = AsyncClient::new(opts, 64);
    Ok(MqttConnection {
        client,
        eventloop,
        info,
    })
}

/// Build the publish envelope matching `mqtt.py:358-416` (`AnkerSolixMqttSession.publish`).
fn build_publish_envelope(info: &MqttInfo, device: &Device, hex_command: &[u8]) -> String {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let payload = json!({
        "device_sn": device.device_sn,
        "account_id": info.user_id,
        "data": BASE64_STANDARD.encode(hex_command),
    });
    let envelope = json!({
        "head": {
            "version": "1.0.0.1",
            "client_id": format!("android-{}-{}-{}", info.app_name, info.user_id, info.certificate_id),
            "sess_id": "1234-5678",
            "msg_seq": 1,
            "seed": "1",
            "timestamp": timestamp,
            "cmd_status": 2,
            "cmd": 17,
            "sign_code": 1,
            "device_pn": device.device_pn,
            "device_sn": device.device_sn,
        },
        "payload": serde_json::to_string(&payload).unwrap(),
    });
    envelope.to_string()
}

/// Publish a realtime-trigger command for `device`, enabling (or disabling)
/// live `0421` updates for `timeout_secs` seconds.
pub async fn publish_realtime_trigger(
    client: &AsyncClient,
    info: &MqttInfo,
    device: &Device,
    enable: bool,
    timeout_secs: u32,
) -> Result<()> {
    let command = c1000gen2::build_realtime_trigger(enable, timeout_secs);
    let topic = format!(
        "{}req",
        topic_prefix(&info.app_name, &device.device_pn, &device.device_sn, true)
    );
    let body = build_publish_envelope(info, device, &command);
    client.publish(topic, QoS::AtMostOnce, false, body).await?;

    Ok(())
}

/// Spawn a background task that subscribes to the device's status topic and
/// keeps writing newly decoded `0421` status into `status` as messages
/// arrive. Also resends the realtime trigger every `timeout_secs - 5`
/// seconds so the device keeps streaming (mirrors `message_poller`'s
/// `restart` check in `mqtt.py:729-732`).
pub fn spawn_monitor(
    mut conn: MqttConnection,
    device: Device,
    timeout_secs: u32,
    status: Arc<RwLock<C1000Gen2Status>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let sub_topic = format!(
            "{}#",
            topic_prefix(&conn.info.app_name, &device.device_pn, &device.device_sn, false)
        );
        if let Err(e) = conn.client.subscribe(sub_topic, QoS::AtMostOnce).await {
            eprintln!("MQTT subscribe failed: {e}");
            return;
        }

        let client = conn.client.clone();
        let info = conn.info.clone();
        let dev = device.clone();
        // Runs for as long as the process does; aborted implicitly on exit.
        let _keepalive = tokio::spawn(async move {
            loop {
                if let Err(e) = publish_realtime_trigger(&client, &info, &dev, true, timeout_secs).await {
                    eprintln!("realtime trigger publish failed: {e}");
                }
                tokio::time::sleep(Duration::from_secs((timeout_secs.saturating_sub(5)).max(1) as u64)).await;
            }
        });

        loop {
            match conn.eventloop.poll().await {
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    if let Some(decoded) = decode_publish(&p.payload) {
                        *status.write().await = decoded;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("MQTT connection error: {e}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    })
}

fn decode_publish(payload: &[u8]) -> Option<C1000Gen2Status> {
    let message: Value = serde_json::from_slice(payload).ok()?;
    let payload_str = message.get("payload")?.as_str()?;
    let payload_json: Value = serde_json::from_str(payload_str).ok()?;
    let data_b64 = payload_json.get("data")?.as_str()?;
    let raw = BASE64_STANDARD.decode(data_b64).ok()?;

    c1000gen2::decode_0421(&raw)
}
