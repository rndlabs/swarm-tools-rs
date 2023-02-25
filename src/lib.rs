use clap::{Parser, Subcommand};
use ethers::prelude::*;
use eyre::Result;
use std::str::FromStr;

pub mod contracts;

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Mine a specific neighborhood overlay address
    MineOverlayAddress(MineOverlayAddress),
    /// Show the first overlay address for all neighborhoods
    DumpOverlayAddresses(DumpOverlayAddresses),
    /// Calculate the overlay address for a given address and nonce
    CalcOverlayAddress(CalcOverlayAddress),
    /// Dump out the funding tear sheet for all wallets
    FundingTearSheet,
    /// Dump out all the stakes from the contract
    DumpAllStakes(DumpAllStakes),
}

#[derive(Parser, Debug, Clone)]
#[clap(name = "bee-miner", version, author, about)]
pub struct Opts {
    #[clap(subcommand)]
    pub subcommand: Commands,
}

#[derive(Parser, Debug, Clone)]
pub struct MineOverlayAddress {
    #[clap(
        short,
        long,
        help = "The target neighborhood to mine for",
        value_parser,
        default_value = "1"
    )]
    pub target: u32,
    #[clap(
        short,
        long,
        help = "The depth for determining neighborhoods",
        value_parser,
        default_value = "8"
    )]
    pub depth: u32,
    #[clap(
        short,
        long,
        help = "The Swarm network ID to mine for",
        value_parser,
        default_value = "1"
    )]
    pub network_id: u64,
    #[clap(
        long,
        help = "The nonce, if any to use for mining",
        value_parser = parse_bytes32,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub nonce: Option<[u8; 32]>,
}

#[derive(Parser, Debug, Clone)]
pub struct CalcOverlayAddress {
    #[clap(
        short,
        long,
        help = "The address to calculate the overlay address for",
        value_parser = parse_name_or_address
    )]
    pub address: H160,
    #[clap(
        short,
        long,
        help = "The Swarm network ID to mine for",
        value_parser,
        default_value = "1"
    )]
    pub network_id: u64,
    #[clap(
        long,
        help = "The nonce, if any to use for mining",
        value_parser = parse_bytes32,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub nonce: Option<[u8; 32]>,
}

#[derive(Parser, Debug, Clone)]
pub struct DumpOverlayAddresses {
    #[clap(
        short,
        long,
        help = "The depth of the neighborhood to mine for",
        value_parser,
        default_value = "8"
    )]
    pub depth: u32,
}

#[derive(Parser, Debug, Clone)]
pub struct DumpAllStakes {
    #[clap(
        short,
        long,
        help = "The address of the stake contract",
        value_parser = parse_name_or_address
    )]
    pub address: H160,
    #[clap(
        short,
        long,
        help = "The RPC endpoint to use",
        value_parser,
        default_value = "http://localhost:8545"
    )]
    pub rpc: String,
    #[clap(
        short,
        long,
        help = "The depth of the neighborhoods",
        value_parser,
        default_value = "8"
    )]
    pub depth: u32
}

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