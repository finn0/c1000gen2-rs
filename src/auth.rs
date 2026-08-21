//! Anker Solix cloud login (read-only monitoring client).
//!
//! Ported from `anker-solix-api/src/anker_solix_api/session.py`. Only the
//! subset needed to authenticate and call a couple of REST endpoints is
//! implemented here (no payload encryption, no request throttling/rate
//! limiting beyond a basic 429 retry) -- see the Rust port plan for scope.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use md5::{Digest, Md5};
use p256::PublicKey;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::RwLock;

use crate::error::{AnkerError, Result};

/// Uncompressed SEC1 point (0x04 || X(32) || Y(32)) of Anker's login public key.
/// Identical for both the EU and COM API servers (session.py:48).
const API_PUBLIC_KEY_HEX: &str = "04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a3868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076";

const API_LOGIN: &str = "passport/login";

/// Ceiling on establishing a TCP+TLS connection to the Anker API.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Ceiling on a whole request, connection included. Generous: these are
/// small JSON calls, so anything near this is a network in trouble rather
/// than a slow response.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

/// Country -> region mapping (apitypes.py:23-98), used to pick the API base URL.
const COM_COUNTRIES: &[&str] = &[
    "DZ", "LB", "SY", "EG", "LY", "TN", "MA", "JO", "PS", "AR", "AU", "BR", "HK", "IN", "MX", "NG", "NZ", "RU", "SG",
    "ZA", "KR", "TW", "US", "CA",
];
/// Listed for documentation parity with `apitypes.py:23-98`; not used for
/// branching since anything not in `COM_COUNTRIES` falls back to EU anyway.
#[allow(dead_code)]
const EU_COUNTRIES: &[&str] = &[
    "DE", "BE", "EL", "LT", "PT", "BG", "ES", "LU", "CZ", "FR", "HU", "SI", "DK", "HR", "MT", "SK", "IT", "NL", "FI",
    "EE", "CY", "AT", "SE", "IE", "LV", "PL", "UK", "IS", "NO", "LI", "CH", "BA", "ME", "MD", "MK", "GE", "AL", "RS",
    "TR", "UA", "XK", "AM", "BY", "AZ", "IL", "RO", "JP",
];

fn api_base_for_country(country: &str) -> &'static str {
    let country = country.to_uppercase();
    if COM_COUNTRIES.contains(&country.as_str()) {
        "https://ankerpower-api.anker.com"
    } else {
        // Everything else -- including EU_COUNTRIES and any unrecognized
        // code -- falls back to the EU server, matching the Python client's
        // behavior (session.py:64-66).
        "https://ankerpower-api-eu.anker.com"
    }
}

fn gmt_offset_string() -> String {
    // Local UTC offset formatted as "GMT+HH:MM" (helpers.py:getTimezoneGMTString)
    let now = chrono::Local::now();
    let offset = now.offset().local_minus_utc();
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.abs();

    format!("GMT{sign}{:02}:{:02}", abs / 3600, (abs % 3600) / 60)
}

fn unix_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}

fn unix_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Discard a cached token this long before it actually expires.
///
/// Guards against a token that is valid when read but dead by the time the
/// request lands, and against modest clock skew between here and Anker.
const TOKEN_EXPIRY_SKEW_SECS: i64 = 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenCache {
    auth_token: String,
    user_id: String,
    token_expires_at: i64,
    #[serde(default)]
    nick_name: String,
}

impl TokenCache {
    /// Whether this token is still worth sending at `now` (unix seconds).
    fn is_usable_at(&self, now: i64) -> bool {
        self.token_expires_at.saturating_sub(TOKEN_EXPIRY_SKEW_SECS) > now
    }
}

pub struct AnkerSession {
    http: reqwest::Client,
    base_url: String,
    country: String,
    email: String,
    password: String,
    cache_path: PathBuf,
    token: RwLock<Option<TokenCache>>,
    shared_secret: Vec<u8>,
    client_public_key_hex: String,
}

impl AnkerSession {
    pub fn new(email: impl Into<String>, password: impl Into<String>, country: impl Into<String>) -> Result<Self> {
        let email = email.into();
        let country = country.into().to_uppercase();

        // Ephemeral ECDH keypair against Anker's fixed server public key.
        let server_public_bytes = hex::decode(API_PUBLIC_KEY_HEX)?;
        let server_public = PublicKey::from_sec1_bytes(&server_public_bytes)
            .map_err(|e| AnkerError::Login(format!("invalid server public key: {e}")))?;
        let secret = EphemeralSecret::random(&mut OsRng);
        let client_public_key_hex = hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
        let shared_secret = secret.diffie_hellman(&server_public).raw_secret_bytes().to_vec();

        let cache_path = PathBuf::from(".authcache").join(format!("{email}.json"));

        // Timeouts are not optional here. `Client::new()` has none at all,
        // so a connection that opens and then goes quiet -- a NAT that
        // dropped the flow, a router rebooting mid-request -- hangs the
        // caller indefinitely. A long-running daemon calls this from its
        // recovery path, which is exactly when the network is least well,
        // and a recovery attempt that never returns is worse than one that
        // fails and gets retried.
        let http = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()?;

        Ok(Self {
            http,
            base_url: api_base_for_country(&country).to_string(),
            country,
            email,
            password: password.into(),
            cache_path,
            token: RwLock::new(None),
            shared_secret,
            client_public_key_hex,
        })
    }

    fn encrypt_password(&self) -> String {
        use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let key = &self.shared_secret[..32];
        let iv = &self.shared_secret[..16];
        let ciphertext = Aes256CbcEnc::new_from_slices(key, iv)
            .expect("AES-256-CBC key/IV lengths are fixed and valid")
            .encrypt_padded_vec::<Pkcs7>(self.password.as_bytes());

        BASE64_STANDARD.encode(ciphertext)
    }

    fn base_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::with_capacity(6);
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            HeaderName::from_static("model-type"),
            HeaderValue::from_static("DESKTOP"),
        );
        headers.insert(
            HeaderName::from_static("app-name"),
            HeaderValue::from_static("anker_power"),
        );
        headers.insert(HeaderName::from_static("os-type"), HeaderValue::from_static("android"));
        headers.insert(
            HeaderName::from_static("country"),
            HeaderValue::from_str(&self.country)?,
        );
        headers.insert(
            HeaderName::from_static("timezone"),
            HeaderValue::from_str(&gmt_offset_string())?,
        );

        Ok(headers)
    }

    /// The cached token, if one is on disk and still usable.
    ///
    /// An expired token is treated as no token at all. A stale one would
    /// still *work* -- `post_json_inner` re-authenticates on 401 -- but only
    /// after spending a doomed round trip, and only for callers that go
    /// through it. Checking here keeps [`login`](Self::login) honest: when
    /// it returns `Ok`, the session really is authenticated.
    async fn load_cache(&self) -> Option<TokenCache> {
        let bytes = tokio::fs::read(&self.cache_path).await.ok()?;
        let token: TokenCache = serde_json::from_slice(&bytes).ok()?;

        token.is_usable_at(unix_secs()).then_some(token)
    }

    async fn save_cache(&self, token: &TokenCache) -> Result<()> {
        if let Some(parent) = self.cache_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes = serde_json::to_vec_pretty(token)?;
        tokio::fs::write(&self.cache_path, bytes).await?;

        Ok(())
    }

    /// Log in, reusing the local token cache when it holds a token that has
    /// not expired. Pass `force = true` to ignore the cache and always
    /// perform a fresh login.
    pub async fn login(&self, force: bool) -> Result<()> {
        if !force && let Some(cached) = self.load_cache().await {
            *self.token.write().await = Some(cached);
            return Ok(());
        }

        self.login_fresh().await
    }

    async fn login_fresh(&self) -> Result<()> {
        let url = format!("{}/{API_LOGIN}", self.base_url);
        let headers = self.base_headers()?;
        let body = json!({
            "ab": self.country,
            "client_secret_info": { "public_key": self.client_public_key_hex },
            "enc": 0,
            "email": self.email,
            "password": self.encrypt_password(),
            "time_zone": local_utc_offset_ms(),
            "transaction": unix_ms().to_string(),
        });

        let resp = self.http.post(&url).headers(headers).json(&body).send().await?;

        let value: Value = resp.json().await?;

        check_api_code(&value)?;

        let data = value.get("data").cloned().unwrap_or(Value::Null);
        let token: TokenCache = serde_json::from_value(data)
            .map_err(|e| AnkerError::Login(format!("unexpected login response shape: {e}")))?;

        self.save_cache(&token).await?;
        *self.token.write().await = Some(token);

        Ok(())
    }

    fn gtoken(user_id: &str) -> String {
        let mut hasher = Md5::new();
        hasher.update(user_id.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// POST an authenticated JSON request against a relative endpoint path,
    /// re-authenticating once on 401/403 and retrying once on 429.
    pub async fn post_json(&self, endpoint: &str, body: Value) -> Result<Value> {
        // Expiry is checked here too, not just at login: a long-running
        // monitor holds one session for weeks, so the in-memory token can
        // age out mid-run. The 401 path below would still recover, but only
        // after a wasted request.
        let needs_login = match self.token.read().await.as_ref() {
            Some(token) => !token.is_usable_at(unix_secs()),
            None => true,
        };
        if needs_login {
            self.login(false).await?;
        }

        self.post_json_inner(endpoint, body, false).await
    }

    async fn post_json_inner(&self, endpoint: &str, body: Value, retried: bool) -> Result<Value> {
        let url = format!("{}/{endpoint}", self.base_url);
        let mut headers = self.base_headers()?;
        if let Some(token) = self.token.read().await.as_ref() {
            headers.insert(
                HeaderName::from_static("x-auth-token"),
                HeaderValue::from_str(&token.auth_token)?,
            );
            headers.insert(
                HeaderName::from_static("gtoken"),
                HeaderValue::from_str(&Self::gtoken(&token.user_id))?,
            );
        }

        let resp = self.http.post(&url).headers(headers).json(&body).send().await?;
        let status = resp.status();

        if (status.as_u16() == 401 || status.as_u16() == 403) && !retried {
            self.login_fresh().await?;
            return Box::pin(self.post_json_inner(endpoint, body, true)).await;
        }
        if status.as_u16() == 429 && !retried {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            return Box::pin(self.post_json_inner(endpoint, body, true)).await;
        }

        let value: Value = resp.json().await?;
        check_api_code(&value)?;
        Ok(value.get("data").cloned().unwrap_or(Value::Null))
    }
}

fn local_utc_offset_ms() -> i64 {
    chrono::Local::now().offset().local_minus_utc() as i64 * 1000
}

fn check_api_code(value: &Value) -> Result<()> {
    let code = value.get("code").and_then(Value::as_i64).unwrap_or(0);
    if code != 0 {
        let message = value
            .get("msg")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
            .to_string();

        return Err(AnkerError::Api { code, message });
    }

    Ok(())
}

#[allow(dead_code)]
fn authcache_dir() -> &'static Path {
    Path::new(".authcache")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(expires_at: i64) -> TokenCache {
        TokenCache {
            auth_token: "t".to_string(),
            user_id: "u".to_string(),
            token_expires_at: expires_at,
            nick_name: String::new(),
        }
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_token_well_before_expiry_is_usable() {
        assert!(token(NOW + 30 * 86400).is_usable_at(NOW));
    }

    #[test]
    fn an_expired_token_is_not_usable() {
        assert!(!token(NOW - 1).is_usable_at(NOW));
    }

    #[test]
    fn a_token_inside_the_skew_window_is_already_treated_as_dead() {
        // Still nominally valid for another half hour, but not long enough
        // to trust with a request.
        assert!(!token(NOW + 1800).is_usable_at(NOW));
        // One second past the skew boundary is fine.
        assert!(token(NOW + TOKEN_EXPIRY_SKEW_SECS + 1).is_usable_at(NOW));
    }

    #[test]
    fn a_nonsense_expiry_does_not_overflow() {
        // Guards the saturating_sub: a corrupt or zeroed cache file must
        // read as unusable rather than panic.
        assert!(!token(i64::MIN).is_usable_at(NOW));
        assert!(!token(0).is_usable_at(NOW));
        assert!(token(i64::MAX).is_usable_at(NOW));
    }

    #[test]
    fn cache_json_from_the_wire_round_trips() {
        // Shape as Anker returns it -- extra fields ignored, nick_name
        // optional.
        let json = r#"{
            "auth_token": "abc",
            "user_id": "def",
            "token_expires_at": 1788738071,
            "unrelated": 1
        }"#;

        let token: TokenCache = serde_json::from_str(json).expect("parses");
        assert_eq!(token.auth_token, "abc");
        assert_eq!(token.token_expires_at, 1788738071);
        assert_eq!(token.nick_name, "");
    }
}
