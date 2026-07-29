//! Error types for the Anker Solix C1000 Gen 2 read-only monitor.

#[derive(Debug, thiserror::Error)]
pub enum AnkerError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON (de)serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("MQTT client error: {0}")]
    Mqtt(#[from] rumqttc::ClientError),

    #[error("MQTT connection error: {0}")]
    MqttConnection(#[from] Box<rumqttc::ConnectionError>),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("invalid HTTP header value: {0}")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),

    #[error("Anker API returned error {code}: {message}")]
    Api { code: i64, message: String },

    #[error("login failed: {0}")]
    Login(String),

    #[error("no C1000 Gen 2 device found in account")]
    DeviceNotFound,

    #[error("MQTT payload decode error: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, AnkerError>;
