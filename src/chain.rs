use ethers::{prelude::*, utils::format_bytes32_string};
use eyre::Result;
use std::{collections::HashMap, str::FromStr, sync::Arc};

use crate::contracts::chain_log::ChainLog;

const CHAINLOG: &str = "0x4989F405b9c449Ccf3FdEa0f60B613afF1E55E14";

pub struct Chain {
    chain_id: u32,
    name: String,
    client: Arc<Provider<Http>>,
    addresses: HashMap<String, H160>,
}

impl Chain {
    pub async fn new(rpc: String) -> Result<Self> {
        let client = Arc::new(Provider::<Http>::try_from(rpc)?);
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

        let (
            postage_stamp_address,
            price_oracle_address,
            redistribution_address,
            stake_registry_address,
        ): (H160, H160, H160, H160) = multicall.call().await?;

        let mut addresses = HashMap::new();
        addresses.insert("POSTAGE_STAMP".to_string(), postage_stamp_address);
        addresses.insert("PRICE_ORACLE".to_string(), price_oracle_address);
        addresses.insert("REDISTRIBUTION".to_string(), redistribution_address);
        addresses.insert("STAKE_REGISTRY".to_string(), stake_registry_address);

        Ok(Self {
            chain_id,
            name: name.to_string(),
            client,
            addresses,
        })
    }

    pub fn get_address(&self, name: &str) -> Option<H160> {
        self.addresses.get(name).clone().copied()
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

    pub fn client(&self) -> Arc<Provider<Http>> {
        self.client.clone()
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
