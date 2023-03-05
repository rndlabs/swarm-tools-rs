use ethers::prelude::*;
use eyre::Result;
use std::str::FromStr;

pub mod contracts;
pub mod overlay;
pub mod redistribution;
pub mod topology;
pub mod postage;

/// A `clap` `value_parser` that parses a `NameOrAddress` from a string
pub fn parse_name_or_address(s: &str) -> Result<H160> {
    Ok(H160::from_str(s)?)
}

/// A `clap` `value_parser` that removes a `0x` prefix if it exists
pub fn strip_0x_prefix(s: &str) -> Result<String, &'static str> {
    Ok(s.strip_prefix("0x").unwrap_or(s).to_string())
}

/// A `clap` `value_parser` that parses a string into a 32 byte array
pub fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    let s = strip_0x_prefix(s)?;
    hex::decode_to_slice(s, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
