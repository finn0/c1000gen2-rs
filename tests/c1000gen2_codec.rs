//! Golden-sample decode test: a real captured `0421` message for a SOLIX
//! C1000 Gen 2 (PN A1763), sourced from an `anker-solix-api` MQTT capture.
//! The device serial number has been replaced with a placeholder (same
//! length, checksum recomputed) to avoid publishing real device identifiers;
//! all other bytes are unmodified.
//!
//! Expected values were produced by running the existing (already
//! device-verified) Python decoder,
//! `DeviceHexData(model="A1763", hexbytes=raw).values()`, against the
//! original payload -- see the Rust port plan for the cross-check
//! methodology.

use c1000gen2_rs::mqtt::c1000gen2::C1000Gen2StatusRaw;

const SAMPLE_BASE64: &str = "/wkmAQMBDwQhoQE0oiEGIBFGQUtFREVWQ0UwMDAwMDAwMAAFQTE3NjMGAgEBAQCjCwQAAAAAsAQAWNwApBsEAAAAALAEMgAAAAAAAAAAHgABAAAAAABkAQOlBgQXAGRkAKYKBAAAAAAAAKsqZKcHBAAAAAEAAKgEBAAAAKoEBAAAAKsEBAAAAKwEBAAAAK4EBAAAALIEBAAAANkaBAAAGWQBAAAAAQAAAAAAAAAAAAAAAAAAAADaGAQAAAAAAAAAAAAAAeABZAV/AAAAAAAAANwGBAAAAAAA+R0EBgIBAQUABQAAAAAABQAFAAUDAAEAAAAAAAICAPoVBAEBAQEAHwMAAAAAAAAAAAAAAAAA/Q4AMTc2NDY1ODM5NzMyOP4FA5ioLmlV";

fn decode_sample() -> C1000Gen2StatusRaw {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(SAMPLE_BASE64)
        .expect("valid base64");
    c1000gen2_rs::mqtt::c1000gen2::decode_0421_raw(&raw).expect("decodes as a 0421 message")
}

#[test]
fn decodes_device_identity() {
    let s = decode_sample();
    assert_eq!(s.device_sn.as_deref(), Some("FAKEDEVCE00000000"));
    assert_eq!(s.device_pn.as_deref(), Some("A1763"));
}

#[test]
fn decodes_battery_fields() {
    let s = decode_sample();
    assert_eq!(s.battery_soc, Some(100.0));
    assert_eq!(s.battery_soh, Some(100.0));
    assert_eq!(s.remaining_time_hours, Some(1092.3));
    assert_eq!(s.temperature, Some(23.0));
}

#[test]
fn decodes_soc_limits() {
    let s = decode_sample();
    assert_eq!(s.max_soc, Some(100.0));
    assert_eq!(s.min_soc, Some(1.0));
}

#[test]
fn decodes_power_fields_idle() {
    let s = decode_sample();
    // Device was idle when this sample was captured: all power flows are 0.
    assert_eq!(s.output_power_total, Some(0.0));
    assert_eq!(s.ac_input_power, Some(0.0));
    assert_eq!(s.dc_input_power_total, Some(0.0));
    assert_eq!(s.ac_output_power, Some(0.0));
    assert_eq!(s.dc_output_power_total, Some(0.0));
}

#[test]
fn decodes_ports_idle() {
    let s = decode_sample();
    assert_eq!(s.usbc_1, Some((0.0, 0.0)));
    assert_eq!(s.usbc_2, Some((0.0, 0.0)));
    assert_eq!(s.usbc_3, Some((0.0, 0.0)));
    assert_eq!(s.usba_1, Some((0.0, 0.0)));
}

#[test]
fn decodes_timestamps() {
    let s = decode_sample();
    assert_eq!(s.msg_timestamp, Some(1764665496.0));
    assert!((s.utc_timestamp.unwrap() - 1764658397.328).abs() < 0.001);
}

#[test]
fn plausible_ranges() {
    let s = decode_sample();
    let soc = s.battery_soc.expect("soc present");
    assert!((0.0..=100.0).contains(&soc));
    let temp = s.temperature.expect("temperature present");
    assert!((-20.0..=80.0).contains(&temp));
}
