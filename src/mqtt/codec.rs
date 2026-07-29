//! Binary TLV codec for Anker Solix MQTT device messages.
//!
//! Ported from `anker-solix-api/src/anker_solix_api/mqtttypes.py`
//! (`DeviceHexDataHeader`, `DeviceHexDataField.__post_init__`). Decode-only:
//! the one command we ever build (the `0057` realtime trigger) is fully
//! hardcoded in `c1000gen2.rs` instead of going through a generic encoder.
//!
//! Verified byte-for-byte against a real captured C1000 Gen 2 message in
//! `tests/c1000gen2_codec.rs` (see that file for the reference dump this was
//! checked against, produced by running the existing Python decoder on the
//! same payload).

use std::collections::HashMap;

/// 9-byte Anker Solix MQTT message header (mqtttypes.py:36-129).
/// `ff09 | msglength(2 LE) | 03 00 0f | msgtype(2)`; header is 10 bytes if an
/// extra "increment" byte follows that isn't itself a field name (a0-a9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgHeader {
    pub msgtype: [u8; 2],
    pub msglength: u16,
}

impl MsgHeader {
    /// Decode the header, returning it plus the number of bytes it occupied
    /// (9 or 10), or `None` if `buf` is too short.
    pub fn decode(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 9 {
            return None;
        }
        let msglength = u16::from_le_bytes([buf[2], buf[3]]);
        let msgtype = [buf[7], buf[8]];
        let header_len = if buf.len() >= 10 && !(0xa0..=0xa9).contains(&buf[9]) {
            10
        } else {
            9
        };
        Some((Self { msgtype, msglength }, header_len))
    }

    pub fn msgtype_hex(&self) -> String {
        hex::encode(self.msgtype)
    }
}

/// Walk the field-boundary TLV structure of a decoded message body and
/// return a map of field-name-byte -> raw value bytes (type byte stripped).
///
/// `buf` must start right after the header and include the trailing XOR
/// checksum byte (matching the slicing behavior of the Python field walker,
/// which peeks past the nominal end of a field's value to disambiguate
/// 1-vs-2-byte length encoding).
pub fn decode_fields(buf: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut fields = HashMap::new();
    let mut idx = 0usize;
    // stop 1 byte before the end: the last byte is the XOR checksum, never a field.
    while idx + 2 < buf.len() {
        let Some((name, value, consumed)) = parse_field(&buf[idx..]) else {
            break;
        };
        if consumed == 0 {
            break;
        }
        fields.insert(name, value);
        idx += consumed;
    }
    fields
}

/// Parse a single field starting at `buf[0]`. Returns (field_name, value_bytes, total_bytes_consumed).
///
/// Field layout: `name(1) + length(1-or-2 bytes LE) + [type(1)] + value`.
/// Numeric types (ui=0x01, sile=0x02, var=0x03, sfle=0x05) always use a
/// 1-byte length; `str`(0x00)/`bin`(0x04) fields have an ambiguous
/// 1-vs-2-byte length resolved via a lookahead heuristic -- ported exactly
/// from `DeviceHexDataField.__post_init__` (mqtttypes.py:150-222), including
/// its slightly odd `bytes(...) < b"10"` type-byte check (equivalent to "is
/// this byte's numeric value <= 0x31", since `b"10"` is the two ASCII bytes
/// 0x31,0x30 -- not the hex value 0x10). Do not "clean up" this comparison,
/// it must match the reference decoder's behavior exactly.
fn parse_field(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let name = buf[0];
    if buf.len() < 3 {
        return None;
    }
    let tentative_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;

    let mut len_bytes = 1usize;
    let f_length: usize;

    let candidate_type = buf.get(3).copied();
    if let Some(ct) = candidate_type
        && (ct == 0x00 || ct == 0x04)
        && tentative_len > 3
        && buf.len() >= 4
        && tentative_len <= buf.len() - 4
    {
        if ct == 0x04 {
            // bin: peek at the byte right after the tentatively-sized value
            // to see if it plausibly starts the next field.
            let next_pos = 3 + tentative_len;
            let next_byte = buf.get(next_pos).copied();
            let remaining_after = buf.len() - tentative_len;
            let looks_like_next_field =
                next_byte.is_some() && (remaining_after == 4 || (next_byte.unwrap() > name && remaining_after >= 3));
            if looks_like_next_field {
                len_bytes = 2;
                f_length = tentative_len;
            } else {
                f_length = buf[1] as usize;
            }
        } else {
            // str: accept the 2-byte length if the presumed string bytes are valid UTF-8.
            let end = 3 + tentative_len;
            if end <= buf.len() && std::str::from_utf8(&buf[4..end]).is_ok() {
                len_bytes = 2;
                f_length = tentative_len;
            } else {
                f_length = buf[1] as usize;
            }
        }
    } else {
        f_length = buf[1] as usize;
    }

    if f_length == 0 || f_length > buf.len().saturating_sub(2) {
        // malformed / end of usable data -- stop the outer walk here.
        return Some((name, Vec::new(), 0));
    }

    let has_type_byte = f_length > 1 && buf.get(1 + len_bytes).is_some_and(|b| *b <= 0x31);
    let value = if has_type_byte {
        let value_start = 2 + len_bytes;
        let value_len = f_length - 1;
        buf.get(value_start..value_start + value_len)?.to_vec()
    } else {
        buf.get(2..2 + f_length)?.to_vec()
    };

    let consumed = 1 + len_bytes + f_length;
    Some((name, value, consumed))
}

/// XOR checksum over all bytes (matches `DeviceHexData._get_xor_checksum`).
pub fn xor_checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, b| acc ^ b)
}
