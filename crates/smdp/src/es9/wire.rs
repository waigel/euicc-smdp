//! Encoding rules the ES9+ JSON binding does not share with ordinary
//! JSON, kept in one place so no handler improvises them.

use serde::{Deserialize, Deserializer, Serializer};

#[derive(Debug)]
pub enum WireError {
    OddLength(usize),
    NotHex(char),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::OddLength(n) => write!(f, "{n} hex digits is not a whole number of bytes"),
            WireError::NotHex(c) => write!(f, "not a hexadecimal digit: {c:?}"),
        }
    }
}

impl std::error::Error for WireError {}

/// SGP.22 v2.6 section 6.5.2.6: `transactionId` matches
/// `^[0-9,A-F]{2,32}$` -- the one payload field that is hexadecimal
/// rather than base64, and upper case at that.
pub fn to_hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, WireError> {
    if s.len() % 2 != 0 {
        return Err(WireError::OddLength(s.len()));
    }
    let d = |c: char| -> Result<u8, WireError> {
        c.to_digit(16).map(|v| v as u8).ok_or(WireError::NotHex(c))
    };
    let cs: Vec<char> = s.chars().collect();
    cs.chunks(2).map(|p| Ok((d(p[0])? << 4) | d(p[1])?)).collect()
}

/// serde adapter for the hexadecimal `transactionId`.
pub mod hex_field {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_hex_upper(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// serde adapter for every other payload field: base64-encoded DER.
pub mod b64_field {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}
