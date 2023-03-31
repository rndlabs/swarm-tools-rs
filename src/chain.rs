use ethers::{prelude::*, utils::format_bytes32_string};
use eyre::Result;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use crate::contracts::chain_log::ChainLog;

const CHAINLOG: &str = "0x4989F405b9c449Ccf3FdEa0f60B613afF1E55E14";
const BZZ_ADDRESS_MAINNET: &str = "0x19062190B1925b5b6689D7073fDfC8c2976EF8Cb";
const BZZ_ADDRESS_GNOSIS: &str = "0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da";

pub struct ChainConfigWithMeta<M> {
    chain_id: u32,
    name: String,
    client: Arc<M>,
    addresses: HashMap<String, H160>,
}

impl<M> ChainConfigWithMeta<M> 
where
    M: Middleware + 'static,
{
    pub async fn new(client: Arc<M>) -> Result<Self> {
        let chain_id = client.get_chainid().await.unwrap().as_u64() as u32;
        let name = match chain_id {
            1 => "mainnet",
            5 => "goerli",
            100 => "gnosis",
            _ => "unknown",
        };

        // Lookup addresses from the ChainLog
        let chainlog = ChainLog::new(H160::from_str(CHAINLOG).unwrap(), client.clone());

        let postage_stamp_address =
            chainlog.get_address(format_bytes32_string("SWARM_POSTAGE_STAMP").unwrap());
        let price_oracle_address =
            chainlog.get_address(format_bytes32_string("SWARM_PRICE_ORACLE").unwrap());
        let redistribution_address =
            chainlog.get_address(format_bytes32_string("SWARM_REDISTRIBUTION").unwrap());
        let stake_registry_address =
            chainlog.get_address(format_bytes32_string("SWARM_STAKE_REGISTRY").unwrap());

        let mut multicall = Multicall::new(client.clone(), None).await?;
        multicall
            .add_call(postage_stamp_address, false)
            .add_call(price_oracle_address, false)
            .add_call(redistribution_address, false)
            .add_call(stake_registry_address, false);

        let result: (Address, Address, Address, Address) = multicall.call().await?;

        let (
            postage_stamp_address,
            price_oracle_address,
            redistribution_address,
            stake_registry_address,
        ) = (result.0, result.1, result.2, result.3);

        let mut addresses = HashMap::new();
        addresses.insert("POSTAGE_STAMP".to_string(), postage_stamp_address);
        addresses.insert("PRICE_ORACLE".to_string(), price_oracle_address);
        addresses.insert("REDISTRIBUTION".to_string(), redistribution_address);
        addresses.insert("STAKE_REGISTRY".to_string(), stake_registry_address);

        // Insert static addresses
        addresses.insert("BZZ_ADDRESS_MAINNET".to_string(), BZZ_ADDRESS_MAINNET.parse()?);
        addresses.insert("BZZ_ADDRESS_GNOSIS".to_string(), BZZ_ADDRESS_GNOSIS.parse()?);

        Ok(Self {
            chain_id,
            name: name.to_string(),
            client,
            addresses,
        })
    }

    pub fn get_address(&self, name: &str) -> Option<H160> {
        self.addresses.get(name).copied()
    }

    /// Returns the block time for the chain
    pub fn block_time(&self) -> u64 {
        match self.chain_id {
            1 => 12,
            5 => 12,
            100 => 5,
            _ => 12,
        }
    }

    pub fn native_units(&self) -> &str {
        match self.chain_id {
            1 => "ETH",
            5 => "ETH",
            100 => "xDAI",
            _ => "ETH",
        }
    }

    pub fn explorer_url(&self, tx_hash: H256) -> (String, String) {
        let tx_hash = format!("0x{}", hex::encode(tx_hash));
        match self.chain_id {
            1 => (
                "Etherscan".to_string(),
                format!("https://etherscan.io/tx/{}", tx_hash),
            ),
            5 => (
                "Etherscan".to_string(),
                format!("https://goerli.etherscan.io/tx/{}", tx_hash),
            ),
            100 => (
                "Gnosisscan".to_string(),
                format!("https://gnosisscan.io/tx/{}", tx_hash),
            ),
            _ => (
                "Etherscan".to_string(),
                format!("https://etherscan.io/tx/{}", tx_hash),
            ),
        }
    }

    pub fn client(&self) -> Arc<M> {
        self.client.clone()
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }
}

impl<M> std::fmt::Display for ChainConfigWithMeta<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
