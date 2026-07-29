//! Device discovery (ported from `apibase.py:get_bind_devices`, endpoint
//! constant `apitypes.py:126`).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::AnkerSession;
use crate::error::Result;

const BIND_DEVICES_ENDPOINT: &str = "power_service/v1/app/get_relate_and_bind_devices";

/// PNs Anker markets as "C1000 Gen 2": A1763 (standard), A1765 (X variant),
/// AS100 (LE variant). All three share the same MQTT field table.
pub const C1000_GEN2_PNS: &[&str] = &["A1763", "A1765", "AS100"];

#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub device_sn: String,
    #[serde(rename = "product_code")]
    pub device_pn: String,
    pub device_name: String,
}

pub async fn list_devices(session: &AnkerSession) -> Result<Vec<Device>> {
    let data = session.post_json(BIND_DEVICES_ENDPOINT, json!({})).await?;
    let items = data.get("data").and_then(Value::as_array).cloned().unwrap_or_default();
    let devices = items
        .into_iter()
        .filter_map(|v| serde_json::from_value::<Device>(v).ok())
        .collect();
    Ok(devices)
}

pub fn find_c1000_gen2(devices: &[Device]) -> Option<&Device> {
    devices.iter().find(|d| C1000_GEN2_PNS.contains(&d.device_pn.as_str()))
}
