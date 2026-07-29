//! SOLIX C1000 Gen 2 family (PN A1763/A1765/AS100): `0421` status decode and
//! `0057` realtime-trigger command builder.
//!
//! Field table transcribed from `_A1763_0421` in
//! `anker-solix-api/src/anker_solix_api/mqttmap.py:381-641`. A1765 (the
//! variant this was actually developed/tested against, PN of the author's
//! own unit) has no dedicated upstream mapping, so -- same workaround as the
//! Python toy script -- this table is applied to all three PNs, which share
//! hardware generation and protocol.
//!
//! Kept in sync with `anker-solix-api/toy/c1000_gen2_status.py`'s
//! `C1000Gen2Status` dataclass: same field set, same bilingual (EN/CN)
//! documentation, same report categories.
//!
//! Decoding is split into two layers:
//! - [`C1000Gen2StatusRaw`]: a byte-level mirror of the wire format --
//!   every field is `Option<f64>`/`Option<String>` (or a raw `(f64, f64)`
//!   tuple for ports), matching `mqttmap.py`'s field types exactly. Produced
//!   by [`decode_0421_raw`].
//! - [`C1000Gen2Status`]: the domain/presentation type built from the raw
//!   one via `From`, with typed fields ([`PortReading`], [`OnOff`],
//!   [`TempUnit`], [`Timestamp`]) that implement `Display` so report
//!   formatting doesn't need per-field wrapper functions. Produced by
//!   [`decode_0421`].

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::codec::{MsgHeader, decode_fields, xor_checksum};

pub const SUPPORTED_PNS: &[&str] = &["A1763", "A1765", "AS100"];

pub const MSG_TYPE_STATUS: [u8; 2] = [0x04, 0x21];
pub const MSG_TYPE_STATUS_ALT: [u8; 2] = [0x09, 0x00]; // "0900": irregular, same content as 0421
const MSG_TYPE_TRIGGER: [u8; 2] = [0x00, 0x57];

/// Decoded values from a `0421` (or `0900`) message, as a byte-level mirror
/// of the wire format -- see the module docs for how this relates to
/// [`C1000Gen2Status`]. Fields are `Option` because not every message
/// carries every field (e.g. `max_soc`/`min_soc` and the expansion-pack
/// fields are only sent occasionally, per live observation against the real
/// device). Values that arrive as raw bytes are stored as `f64`/`String`
/// here already converted -- unlike the Python toy script, there's no
/// "sometimes a string, sometimes a number" ambiguity since we decode
/// straight from the wire.
#[derive(Debug, Clone, Default)]
pub struct C1000Gen2StatusRaw {
    // --- Device identity / (field a2, static, doesn't change) ---
    /// Device serial number
    pub device_sn: Option<String>,
    /// Device product model number
    pub device_pn: Option<String>,

    // --- Battery / (fields a5, a6) ---
    /// Battery state of charge, %. When a B1000 expansion pack is attached,
    /// this is the combined/overall reading across the main unit and the
    /// pack(s) -- not just the main unit alone (see `main_battery_soc` for
    /// that). Inferred from `apibase.py`'s cross-model fallback calculation
    /// (not A1763-specific code, but the same field semantics): when a
    /// device doesn't report a combined value directly, the library
    /// synthesizes `battery_soc` as the average of `main_battery_soc` and
    /// each `exp_N_soc`. Without an expansion pack attached, expect this to
    /// equal `main_battery_soc`.
    pub battery_soc: Option<f64>,
    /// Battery state of health, %
    pub battery_soh: Option<f64>,
    /// Device temperature, Celsius
    pub temperature: Option<f64>,
    /// Estimated remaining runtime, hours
    pub remaining_time_hours: Option<f64>,
    /// SOC of the main unit's own battery cell only, excluding any attached
    /// B1000 expansion pack (see `exp_1_soc` for that) -- distinct from the
    /// combined/overall `battery_soc` above. Without an expansion pack
    /// attached, expect this to equal `battery_soc`.
    pub main_battery_soc: Option<f64>,

    // --- Power flows (fields a6, a7, a8) ---
    /// Total output power, AC+DC combined, W
    pub output_power_total: Option<f64>,
    /// AC charging input power, W
    pub ac_input_power_total: Option<f64>,
    /// Duplicate of ac_input_power_total, sourced from field a7 instead of a6
    pub ac_input_power: Option<f64>,
    /// AC input (charging) on(1)/off(0)
    pub ac_input_power_switch: Option<f64>,
    /// DC input power, solar/car charging combined, W
    pub dc_input_power_total: Option<f64>,
    /// AC output power, W
    pub ac_output_power: Option<f64>,
    /// NOT a rollup of USB port power (those are tracked separately below).
    /// It's independently switched (its own on-wire "dc_output_power_switch")
    /// and only moves with load on that specific port -- a separate DC
    /// output circuit from the USB-C/USB-A ports.
    pub dc_output_power_total: Option<f64>,

    // --- Ports (fields aa, ab, ac, ae): (status, power); status is 0=idle 1=discharging 2=charging ---
    /// USB-C port 1 (status, power W)
    pub usbc_1: Option<(f64, f64)>,
    /// USB-C port 2 (status, power W)
    pub usbc_2: Option<(f64, f64)>,
    /// USB-C port 3 (status, power W)
    pub usbc_3: Option<(f64, f64)>,
    /// USB-A port 1 (status, power W)
    pub usba_1: Option<(f64, f64)>,

    // --- SOC limits, i.e. charge/discharge protection settings ---
    /// Max charge limit, %, one of 80/85/90/95/100
    pub max_soc: Option<f64>,
    /// Min discharge limit, %, one of 1/5/10/15/20
    pub min_soc: Option<f64>,

    // --- Switch states (fields a7, a8, b2, a4) ---
    /// AC output on(1)/off(0)
    pub ac_output_power_switch: Option<f64>,
    /// DC input on(1)/off(0)
    pub dc_input_power_switch: Option<f64>,
    /// DC output on(1)/off(0)
    pub dc_output_power_switch: Option<f64>,
    /// Display on(1)/off(0)
    pub display_switch: Option<f64>,
    /// Ultra-fast AC charge switch, on(1)/off(0)
    pub ac_fast_charge_switch: Option<f64>,
    /// Output port memory switch, on(1)/off(0)
    pub port_memory_switch: Option<f64>,

    // --- Config / settings, mostly static unless changed via the App (fields a3, a4) ---
    /// AC charge limit, W, 100-1200 step 100
    pub ac_input_limit: Option<f64>,
    /// Max supported AC charge limit, appears fixed per unit
    pub ac_input_limit_max: Option<f64>,
    /// AC output frequency, 50 or 60 Hz
    pub ac_frequency: Option<f64>,
    /// AC output mode: 0=normal 1=smart (auto-off below 14W)
    pub ac_output_mode: Option<f64>,
    /// AC output auto-off timeout, seconds
    pub ac_output_timeout_seconds: Option<f64>,
    /// 12V DC output mode: 0=normal 1=smart (auto-off below 3W)
    pub dc_12v_output_mode: Option<f64>,
    /// DC output auto-off timeout, seconds
    pub dc_output_timeout_seconds: Option<f64>,
    /// Device auto-shutdown timeout, minutes
    pub device_timeout_minutes: Option<f64>,
    /// Display auto-off timeout, seconds
    pub display_timeout_seconds: Option<f64>,
    /// Display brightness: 1=low 2=medium 3=high
    pub display_mode: Option<f64>,
    /// Temperature unit: 0=Celsius 1=Fahrenheit
    pub temp_unit_fahrenheit: Option<f64>,

    // --- Expansion pack, only present if a B1000 pack is attached ---
    /// Expansion pack serial number
    pub exp_1_sn: Option<String>,
    /// Expansion pack temperature, Celsius
    pub exp_1_temperature: Option<f64>,
    /// Expansion pack state of charge, %
    pub exp_1_soc: Option<f64>,
    /// Expansion pack type code
    pub exp_1_type: Option<String>,

    // --- Timestamps (fields fd, fe) ---
    /// Message UTC timestamp, seconds since epoch, from the device's own
    /// clock -- NOT confirmed to track real time continuously; observed to
    /// lag behind `msg_timestamp` by anywhere from ~2 hours to several days
    /// across different captures, so it's more likely a periodic sync
    /// checkpoint than a live clock. Prefer `msg_timestamp` for freshness.
    pub utc_timestamp: Option<f64>,
    /// Message timestamp, seconds since epoch
    pub msg_timestamp: Option<f64>,

    // --- Unverified fields, meaning not confirmed by upstream library, use with caution (field da) ---
    /// Meaning unconfirmed
    pub unknown_2: Option<f64>,
    /// Meaning unconfirmed
    pub unknown_3: Option<f64>,
}

/// USB port charge/discharge state, decoded from the wire's `0`/`1`/`2`
/// status code. `Unknown` preserves the raw code for any value outside that
/// range instead of silently dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PortStatus {
    Idle,
    Discharging,
    Charging,
    Unknown(u8),
}

impl From<f64> for PortStatus {
    fn from(v: f64) -> Self {
        match v as i64 {
            0 => Self::Idle,
            1 => Self::Discharging,
            2 => Self::Charging,
            other => Self::Unknown(other as u8),
        }
    }
}

impl fmt::Display for PortStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Discharging => write!(f, "Discharging"),
            Self::Charging => write!(f, "Charging"),
            Self::Unknown(code) => write!(f, "Unknown({code})"),
        }
    }
}

/// A single USB port's reading: charge/discharge state plus power draw.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct PortReading {
    pub status: PortStatus,
    pub power_w: f64,
}

impl From<(f64, f64)> for PortReading {
    fn from((status, power_w): (f64, f64)) -> Self {
        Self {
            status: status.into(),
            power_w,
        }
    }
}

impl fmt::Display for PortReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {} W", self.status, self.power_w)
    }
}

/// A binary switch state, decoded from the wire's `0`/non-`0` convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OnOff {
    On,
    Off,
}

impl From<f64> for OnOff {
    fn from(v: f64) -> Self {
        if v != 0.0 { Self::On } else { Self::Off }
    }
}

impl fmt::Display for OnOff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::On => write!(f, "On"),
            Self::Off => write!(f, "Off"),
        }
    }
}

/// Device temperature display unit, decoded from the wire's `0`/`1` convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TempUnit {
    Celsius,
    Fahrenheit,
}

impl From<f64> for TempUnit {
    fn from(v: f64) -> Self {
        if v != 0.0 { Self::Fahrenheit } else { Self::Celsius }
    }
}

impl fmt::Display for TempUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Celsius => write!(f, "C"),
            Self::Fahrenheit => write!(f, "F"),
        }
    }
}

/// Seconds-since-epoch timestamp, displayed in local computer time.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize)]
pub struct Timestamp(pub f64);

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(dt) = chrono::DateTime::from_timestamp(self.0 as i64, 0) else {
            return write!(f, "invalid timestamp {}", self.0);
        };
        write!(f, "{}", dt.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S"))
    }
}

/// Decoded, domain-typed values from a `0421` (or `0900`) message -- see the
/// module docs. Built from [`C1000Gen2StatusRaw`] via `From`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct C1000Gen2Status {
    pub device_sn: Option<String>,
    pub device_pn: Option<String>,

    pub battery_soc: Option<f64>,
    pub battery_soh: Option<f64>,
    pub temperature: Option<f64>,
    pub remaining_time_hours: Option<f64>,
    pub main_battery_soc: Option<f64>,

    pub output_power_total: Option<f64>,
    pub ac_input_power_total: Option<f64>,
    pub ac_input_power: Option<f64>,
    pub ac_input_power_switch: Option<OnOff>,
    pub dc_input_power_total: Option<f64>,
    pub ac_output_power: Option<f64>,
    pub dc_output_power_total: Option<f64>,

    pub usbc_1: Option<PortReading>,
    pub usbc_2: Option<PortReading>,
    pub usbc_3: Option<PortReading>,
    pub usba_1: Option<PortReading>,

    pub max_soc: Option<f64>,
    pub min_soc: Option<f64>,

    pub ac_output_power_switch: Option<OnOff>,
    pub dc_input_power_switch: Option<OnOff>,
    pub dc_output_power_switch: Option<OnOff>,
    pub display_switch: Option<OnOff>,
    pub ac_fast_charge_switch: Option<OnOff>,
    pub port_memory_switch: Option<OnOff>,

    pub ac_input_limit: Option<f64>,
    pub ac_input_limit_max: Option<f64>,
    pub ac_frequency: Option<f64>,
    pub ac_output_mode: Option<f64>,
    pub ac_output_timeout_seconds: Option<f64>,
    pub dc_12v_output_mode: Option<f64>,
    pub dc_output_timeout_seconds: Option<f64>,
    pub device_timeout_minutes: Option<f64>,
    pub display_timeout_seconds: Option<f64>,
    pub display_mode: Option<f64>,
    /// Temperature display unit. Renamed from the raw `temp_unit_fahrenheit`
    /// field now that the type itself says what it means.
    pub temp_unit: Option<TempUnit>,

    pub exp_1_sn: Option<String>,
    pub exp_1_temperature: Option<f64>,
    pub exp_1_soc: Option<f64>,
    pub exp_1_type: Option<String>,

    pub utc_timestamp: Option<Timestamp>,
    pub msg_timestamp: Option<Timestamp>,

    pub unknown_2: Option<f64>,
    pub unknown_3: Option<f64>,
}

impl From<C1000Gen2StatusRaw> for C1000Gen2Status {
    fn from(r: C1000Gen2StatusRaw) -> Self {
        Self {
            device_sn: r.device_sn,
            device_pn: r.device_pn,

            battery_soc: r.battery_soc,
            battery_soh: r.battery_soh,
            temperature: r.temperature,
            remaining_time_hours: r.remaining_time_hours,
            main_battery_soc: r.main_battery_soc,

            output_power_total: r.output_power_total,
            ac_input_power_total: r.ac_input_power_total,
            ac_input_power: r.ac_input_power,
            ac_input_power_switch: r.ac_input_power_switch.map(Into::into),
            dc_input_power_total: r.dc_input_power_total,
            ac_output_power: r.ac_output_power,
            dc_output_power_total: r.dc_output_power_total,

            usbc_1: r.usbc_1.map(Into::into),
            usbc_2: r.usbc_2.map(Into::into),
            usbc_3: r.usbc_3.map(Into::into),
            usba_1: r.usba_1.map(Into::into),

            max_soc: r.max_soc,
            min_soc: r.min_soc,

            ac_output_power_switch: r.ac_output_power_switch.map(Into::into),
            dc_input_power_switch: r.dc_input_power_switch.map(Into::into),
            dc_output_power_switch: r.dc_output_power_switch.map(Into::into),
            display_switch: r.display_switch.map(Into::into),
            ac_fast_charge_switch: r.ac_fast_charge_switch.map(Into::into),
            port_memory_switch: r.port_memory_switch.map(Into::into),

            ac_input_limit: r.ac_input_limit,
            ac_input_limit_max: r.ac_input_limit_max,
            ac_frequency: r.ac_frequency,
            ac_output_mode: r.ac_output_mode,
            ac_output_timeout_seconds: r.ac_output_timeout_seconds,
            dc_12v_output_mode: r.dc_12v_output_mode,
            dc_output_timeout_seconds: r.dc_output_timeout_seconds,
            device_timeout_minutes: r.device_timeout_minutes,
            display_timeout_seconds: r.display_timeout_seconds,
            display_mode: r.display_mode,
            temp_unit: r.temp_unit_fahrenheit.map(Into::into),

            exp_1_sn: r.exp_1_sn,
            exp_1_temperature: r.exp_1_temperature,
            exp_1_soc: r.exp_1_soc,
            exp_1_type: r.exp_1_type,

            utc_timestamp: r.utc_timestamp.map(Timestamp),
            msg_timestamp: r.msg_timestamp.map(Timestamp),

            unknown_2: r.unknown_2,
            unknown_3: r.unknown_3,
        }
    }
}

/// One labeled value within a [`StatusSection`]. `value` is `None` when the
/// field wasn't present in the most recent decoded message -- the row is
/// still included so a rendered table keeps a stable set of rows across
/// poll cycles instead of fields flickering in and out.
#[derive(Debug, Clone, Serialize)]
pub struct StatusRow {
    pub label: &'static str,
    pub value: Option<String>,
}

/// A titled group of [`StatusRow`]s, e.g. "Battery" or "Ports". See
/// [`C1000Gen2Status::sections`].
#[derive(Debug, Clone, Serialize)]
pub struct StatusSection {
    pub title: &'static str,
    pub rows: Vec<StatusRow>,
}

impl From<(&'static str, Option<String>)> for StatusRow {
    fn from((label, value): (&'static str, Option<String>)) -> Self {
        Self { label, value }
    }
}

/// Formats an `Option<T>` as `Option<String>` via `T`'s own `Display` impl,
/// so report rows never need a per-field wrapper function.
trait OptDisplay {
    fn to_display(&self) -> Option<String>;
}

impl<T: fmt::Display> OptDisplay for Option<T> {
    fn to_display(&self) -> Option<String> {
        self.as_ref().map(ToString::to_string)
    }
}

impl C1000Gen2Status {
    /// Every report section, in display order, as structured data -- e.g.
    /// for serializing to JSON for a web frontend. Every row is included
    /// even when its value is currently `None`, so consumers get a stable
    /// row set across poll cycles; only the "Expansion pack" section is
    /// conditional, since that's a structural fact (no B1000 attached) --
    /// not a per-cycle data gap.
    pub fn sections(&self) -> Vec<StatusSection> {
        let mut out = vec![
            self.battery_section(),
            self.power_section(),
            self.port_section(),
            self.soc_limit_section(),
            self.switch_section(),
            self.settings_section(),
            self.timestamp_section(),
        ];

        if self.exp_1_sn.is_some() || self.exp_1_soc.is_some() {
            out.push(self.expansion_section());
        }

        out.push(self.unverified_section());
        out
    }

    /// Full categorized report across every field, with a local-computer-time header.
    pub fn format_full(&self) -> String {
        let local_now = chrono::Local::now().format("%l:%M %p %A, %B %e, %Y (%Z)");
        let mut out = format!("===== C1000 Gen 2 Status @ local time {local_now} =====\n");
        for section in self.sections() {
            push_section(&mut out, &section);
        }
        out
    }

    /// Battery-only report (SOC/SOH/temperature/remaining time).
    pub fn format_battery(&self) -> String {
        let mut out = String::new();
        push_section(&mut out, &self.battery_section());
        out
    }

    /// Power-flows-only report (total/AC/DC in/out).
    pub fn format_power(&self) -> String {
        let mut out = String::new();
        push_section(&mut out, &self.power_section());
        out
    }

    /// Ports-only report (USB-C x3, USB-A x1).
    pub fn format_ports(&self) -> String {
        let mut out = String::new();
        push_section(&mut out, &self.port_section());
        out
    }

    /// Timestamps-only report.
    pub fn format_timestamps(&self) -> String {
        let mut out = String::new();
        push_section(&mut out, &self.timestamp_section());
        out
    }

    fn battery_section(&self) -> StatusSection {
        StatusSection {
            title: "Battery",
            rows: vec![
                ("SOC %", self.battery_soc.to_display()),
                ("Main cell SOC %", self.main_battery_soc.to_display()),
                ("SOH %", self.battery_soh.to_display()),
                ("Temp °C", self.temperature.to_display()),
                ("Temp °F", self.temperature.map(celsius_to_fahrenheit).to_display()),
                ("Remaining h", self.remaining_time_hours.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn power_section(&self) -> StatusSection {
        StatusSection {
            title: "Power",
            rows: vec![
                ("Total Out W", self.output_power_total.to_display()),
                ("AC Out W", self.ac_output_power.to_display()),
                ("AC In W", self.ac_input_power_total.to_display()),
                ("DC In W", self.dc_input_power_total.to_display()),
                ("DC Out W", self.dc_output_power_total.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn port_section(&self) -> StatusSection {
        StatusSection {
            title: "Ports",
            rows: vec![
                ("USB-C 1", self.usbc_1.to_display()),
                ("USB-C 2", self.usbc_2.to_display()),
                ("USB-C 3", self.usbc_3.to_display()),
                ("USB-A 1", self.usba_1.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn timestamp_section(&self) -> StatusSection {
        StatusSection {
            title: "Timestamps",
            rows: vec![
                ("Device UTC", self.utc_timestamp.to_display()),
                ("Message time", self.msg_timestamp.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn soc_limit_section(&self) -> StatusSection {
        StatusSection {
            title: "SOC limits",
            rows: vec![
                ("Max %", self.max_soc.to_display()),
                ("Min %", self.min_soc.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn switch_section(&self) -> StatusSection {
        StatusSection {
            title: "Switches",
            rows: vec![
                ("AC output", self.ac_output_power_switch.to_display()),
                ("AC input", self.ac_input_power_switch.to_display()),
                ("DC input", self.dc_input_power_switch.to_display()),
                ("DC output", self.dc_output_power_switch.to_display()),
                ("Display", self.display_switch.to_display()),
                ("Fast charge", self.ac_fast_charge_switch.to_display()),
                ("Port memory", self.port_memory_switch.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn settings_section(&self) -> StatusSection {
        StatusSection {
            title: "Settings",
            rows: vec![
                ("AC charge limit W", self.ac_input_limit.to_display()),
                ("AC charge limit max W", self.ac_input_limit_max.to_display()),
                ("AC frequency Hz", self.ac_frequency.to_display()),
                ("AC output mode", self.ac_output_mode.to_display()),
                ("AC output timeout s", self.ac_output_timeout_seconds.to_display()),
                ("DC 12V mode", self.dc_12v_output_mode.to_display()),
                ("DC output timeout s", self.dc_output_timeout_seconds.to_display()),
                ("Device timeout min", self.device_timeout_minutes.to_display()),
                ("Display timeout s", self.display_timeout_seconds.to_display()),
                ("Display mode", self.display_mode.to_display()),
                ("Temp unit", self.temp_unit.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn expansion_section(&self) -> StatusSection {
        StatusSection {
            title: "Expansion pack",
            rows: vec![
                ("Serial", self.exp_1_sn.to_display()),
                ("Type", self.exp_1_type.to_display()),
                ("Temp °C", self.exp_1_temperature.to_display()),
                ("SOC %", self.exp_1_soc.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }

    fn unverified_section(&self) -> StatusSection {
        StatusSection {
            title: "Unverified",
            rows: vec![
                ("Unknown 2", self.unknown_2.to_display()),
                ("Unknown 3", self.unknown_3.to_display()),
            ]
            .into_iter()
            .map(StatusRow::from)
            .collect(),
        }
    }
}

/// Read an unsigned 1-byte ("ui") value at `offset` within `field`.
fn ui(field: &[u8], offset: usize) -> Option<f64> {
    field.get(offset).map(|b| *b as f64)
}

/// Read a 2-byte little-endian ("sile") value at `offset`, signed unless `signed` is false.
fn sile(field: &[u8], offset: usize, signed: bool, factor: f64) -> Option<f64> {
    let bytes = field.get(offset..offset + 2)?;
    let raw = i16::from_le_bytes([bytes[0], bytes[1]]);
    let value = if signed {
        raw as f64
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]]) as f64
    };
    Some(value * factor)
}

/// Read a 4-byte little-endian ("var") value at `offset`.
fn var4(field: &[u8], offset: usize, signed: bool) -> Option<f64> {
    let bytes = field.get(offset..offset + 4)?;
    let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
    Some(if signed {
        i32::from_le_bytes(arr) as f64
    } else {
        u32::from_le_bytes(arr) as f64
    })
}

/// Read a self-length-prefixed string at `offset`: 1 length byte followed by that many bytes.
fn str_self_len(field: &[u8], offset: usize) -> Option<(String, usize)> {
    let len = *field.get(offset)? as usize;
    let bytes = field.get(offset + 1..offset + 1 + len)?;
    Some((String::from_utf8_lossy(bytes).to_string(), 1 + len))
}

/// Decode a `0421`/`0900` message into the domain-typed [`C1000Gen2Status`].
pub fn decode_0421(bytes: &[u8]) -> Option<C1000Gen2Status> {
    decode_0421_raw(bytes).map(Into::into)
}

/// Decode a `0421`/`0900` message into the wire-accurate [`C1000Gen2StatusRaw`].
pub fn decode_0421_raw(bytes: &[u8]) -> Option<C1000Gen2StatusRaw> {
    let (header, header_len) = MsgHeader::decode(bytes)?;
    if header.msgtype != MSG_TYPE_STATUS && header.msgtype != MSG_TYPE_STATUS_ALT {
        return None;
    }
    let fields = decode_fields(&bytes[header_len..]);
    Some(decode_fields_to_raw(&fields))
}

// NOTE: mqttmap.py's BYTES sub-dict keys are plain decimal strings parsed via
// Python's `int(key)`, not hex -- e.g. key "20" means absolute offset 20
// (decimal), not 0x20 (32). All offsets below are decimal to match. Verified
// against 103 real captured messages (see tests/c1000gen2_codec.rs).
fn decode_fields_to_raw(fields: &HashMap<u8, Vec<u8>>) -> C1000Gen2StatusRaw {
    let mut s = C1000Gen2StatusRaw::default();

    if let Some(a2) = fields.get(&0xa2) {
        if let Some((sn, _)) = str_self_len(a2, 1) {
            s.device_sn = Some(sn);
        }
        if let Some((pn, _)) = str_self_len(a2, 20) {
            s.device_pn = Some(pn);
        }
    }

    if let Some(a3) = fields.get(&0xa3) {
        s.ac_input_limit_max = sile(a3, 4, true, 1.0);
    }

    if let Some(a4) = fields.get(&0xa4) {
        s.ac_output_timeout_seconds = var4(a4, 0, false);
        s.ac_input_limit = sile(a4, 4, true, 1.0);
        s.ac_frequency = ui(a4, 6);
        s.ac_output_mode = ui(a4, 7);
        s.dc_output_timeout_seconds = var4(a4, 8, false);
        s.dc_12v_output_mode = ui(a4, 12);
        s.device_timeout_minutes = sile(a4, 13, true, 1.0);
        s.display_timeout_seconds = sile(a4, 15, true, 1.0);
        s.display_mode = ui(a4, 17);
        s.temp_unit_fahrenheit = ui(a4, 19);
        s.ac_fast_charge_switch = ui(a4, 20);
        s.display_switch = ui(a4, 21);
        s.port_memory_switch = ui(a4, 22);
    }

    if let Some(a5) = fields.get(&0xa5) {
        s.temperature = ui(a5, 0);
        s.battery_soc = ui(a5, 2);
        s.battery_soh = ui(a5, 3);
    }

    if let Some(a6) = fields.get(&0xa6) {
        s.output_power_total = sile(a6, 0, true, 1.0);
        s.ac_input_power_total = sile(a6, 2, true, 1.0);
        s.dc_input_power_total = sile(a6, 4, true, 1.0);
        s.remaining_time_hours = sile(a6, 6, false, 0.1);
        s.main_battery_soc = ui(a6, 8);
    }

    if let Some(a7) = fields.get(&0xa7) {
        s.ac_output_power_switch = ui(a7, 0);
        s.ac_output_power = sile(a7, 1, true, 1.0);
        s.ac_input_power_switch = ui(a7, 3);
        s.ac_input_power = sile(a7, 4, true, 1.0);
    }

    if let Some(a8) = fields.get(&0xa8) {
        s.dc_input_power_switch = ui(a8, 0);
        // duplicate of a6's dc_input_power_total; prefer it if a6 was absent
        if s.dc_input_power_total.is_none() {
            s.dc_input_power_total = sile(a8, 1, true, 1.0);
        }
    }

    if let (Some(aa_status), Some(aa_power)) = (
        fields.get(&0xaa).and_then(|f| ui(f, 0)),
        fields.get(&0xaa).and_then(|f| sile(f, 1, true, 1.0)),
    ) {
        s.usbc_1 = Some((aa_status, aa_power));
    }
    if let (Some(ab_status), Some(ab_power)) = (
        fields.get(&0xab).and_then(|f| ui(f, 0)),
        fields.get(&0xab).and_then(|f| sile(f, 1, true, 1.0)),
    ) {
        s.usbc_2 = Some((ab_status, ab_power));
    }
    if let (Some(ac_status), Some(ac_power)) = (
        fields.get(&0xac).and_then(|f| ui(f, 0)),
        fields.get(&0xac).and_then(|f| sile(f, 1, true, 1.0)),
    ) {
        s.usbc_3 = Some((ac_status, ac_power));
    }
    if let (Some(ae_status), Some(ae_power)) = (
        fields.get(&0xae).and_then(|f| ui(f, 0)),
        fields.get(&0xae).and_then(|f| sile(f, 1, true, 1.0)),
    ) {
        s.usba_1 = Some((ae_status, ae_power));
    }

    if let Some(b2) = fields.get(&0xb2) {
        s.dc_output_power_switch = ui(b2, 0);
        s.dc_output_power_total = sile(b2, 1, true, 1.0);
    }

    if let Some(d9) = fields.get(&0xd9) {
        s.max_soc = ui(d9, 3);
        s.min_soc = ui(d9, 4);
    }

    // c0: expansion pack (B1000), relative-offset chain: exp_1_sn(str, self-len) ->
    // exp_1_temperature(ui, OFFSET 5) -> exp_1_soc(ui, OFFSET 1) -> exp_1_type(str, OFFSET 6).
    if let Some(c0) = fields.get(&0xc0)
        && let Some((sn, sn_consumed)) = str_self_len(c0, 0)
    {
        s.exp_1_sn = Some(sn);
        let mut pos = sn_consumed;
        pos += 5; // exp_1_temperature's OFFSET
        s.exp_1_temperature = ui(c0, pos);
        pos += 1; // consumed: exp_1_temperature's own 1-byte (ui) value
        pos += 1; // exp_1_soc's OFFSET
        s.exp_1_soc = ui(c0, pos);
        pos += 1; // consumed: exp_1_soc's own 1-byte (ui) value
        pos += 6; // exp_1_type's OFFSET
        if let Some((ty, _)) = str_self_len(c0, pos) {
            s.exp_1_type = Some(ty);
        }
    }

    if let Some(da) = fields.get(&0xda) {
        s.unknown_2 = sile(da, 12, true, 1.0);
        s.unknown_3 = sile(da, 14, true, 1.0);
    }

    if let Some(fd) = fields.get(&0xfd) {
        // ASCII ms-timestamp string -> seconds
        if let Ok(s_str) = std::str::from_utf8(fd)
            && let Ok(ms) = s_str.trim().parse::<f64>()
        {
            s.utc_timestamp = Some(ms / 1000.0);
        }
    }
    if let Some(fe) = fields.get(&0xfe)
        && fe.len() == 4
    {
        s.msg_timestamp = Some(u32::from_le_bytes([fe[0], fe[1], fe[2], fe[3]]) as f64);
    }

    s
}

// ---------------------------------------------------------------------
// Bilingual, categorized report formatting -- mirrors
// anker-solix-api/toy/c1000_gen2_status.py's C1000Gen2Status.format_report()
// and its per-category helpers.
// ---------------------------------------------------------------------

fn celsius_to_fahrenheit(c: f64) -> f64 {
    c * 9.0 / 5.0 + 32.0
}

/// Append a titled section to `out` with aligned `label : value` rows,
/// skipping rows whose value is `None`. Emits nothing if all rows are empty.
fn push_section(out: &mut String, section: &StatusSection) {
    let shown: Vec<&StatusRow> = section.rows.iter().filter(|row| row.value.is_some()).collect();
    if shown.is_empty() {
        return;
    }
    out.push_str(&format!("-- {} --\n", section.title));
    let width = shown.iter().map(|row| row.label.chars().count()).max().unwrap_or(0);
    for row in shown {
        let label = row.label;
        let value = row.value.as_ref().unwrap();
        out.push_str(&format!("  {label:<width$} : {value}\n"));
    }
}

/// Build the raw hex bytes for a `0057` realtime-trigger publish command,
/// matching the concrete example in `mqtt.py:1158-1175` /
/// `mqttcmdmap.py:235-251`:
///   a1 = raw `01 22` (fixed pattern byte)
///   a2 = ui, 1 (on) / 0 (off)
///   a3 = var, 4-byte LE timeout in seconds
///   fe = var, 4-byte LE unix timestamp in seconds
/// followed by a header with the correct `msglength` and a trailing XOR
/// checksum byte.
pub fn build_realtime_trigger(enable: bool, timeout_secs: u32) -> Vec<u8> {
    let mut fields = Vec::new();
    // a1: fixed "pattern_22" field, raw bytes 01 22 following the name byte.
    fields.extend_from_slice(&[0xa1, 0x01, 0x22]);
    // a2: ui type (0x01), 1-byte value.
    fields.extend_from_slice(&[0xa2, 0x02, 0x01, if enable { 1 } else { 0 }]);
    // a3: var type (0x03), 4-byte LE value -> f_length = 1(type) + 4(value) = 5.
    fields.push(0xa3);
    fields.push(0x05);
    fields.push(0x03);
    fields.extend_from_slice(&timeout_secs.to_le_bytes());
    // fe: var type (0x03), 4-byte LE unix timestamp in seconds.
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
    fields.push(0xfe);
    fields.push(0x05);
    fields.push(0x03);
    fields.extend_from_slice(&now_secs.to_le_bytes());

    let msglength = 9 + fields.len() + 1; // header + fields + checksum byte
    let mut msg = Vec::with_capacity(msglength);
    msg.extend_from_slice(&[0xff, 0x09]);
    msg.extend_from_slice(&(msglength as u16).to_le_bytes());
    msg.extend_from_slice(&[0x03, 0x00, 0x0f]);
    msg.extend_from_slice(&MSG_TYPE_TRIGGER);
    msg.extend_from_slice(&fields);
    let checksum = xor_checksum(&msg);
    msg.push(checksum);

    msg
}
