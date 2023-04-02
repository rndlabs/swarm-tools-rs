use ethers::{prelude::*, utils::format_bytes32_string};
use eyre::{anyhow, Result};
use std::{collections::HashMap, str::FromStr, sync::Arc};

use crate::contracts::chain_log::ChainLog;

const CHAINLOG: &str = "0x4989F405b9c449Ccf3FdEa0f60B613afF1E55E14";
const BZZ_ADDRESS_MAINNET: &str = "0x19062190B1925b5b6689D7073fDfC8c2976EF8Cb";
const BZZ_ADDRESS_GNOSIS: &str = "0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da";
const BONDING_CURVE_MAINNET: &str = "0x4f32ab778e85c4ad0cead54f8f82f5ee74d46904";
const DAI_ADDRESS_MAINNET: &str = "0x6B175474E89094C44Da98b954EedeAC495271d0F";

const XDAI_BRIDGE_MAINNET: &str = "0x4aa42145Aa6Ebf72e164C9bBC74fbD3788045016";
const XDAI_BRIDGE_GNOSIS: &str = "0x7301CFA0e1756B71869E93d4e4Dca5c7d0eb0AA6";

const OMNI_BRIDGE_MAINNET: &str = "0x88ad09518695c6c3712AC10a214bE5109a655671";
const OMNI_BRIDGE_GNOSIS: &str = "0xf6A78083ca3e2a662D6dd1703c939c8aCE2e268d";

const AMB_GNOSIS: &str = "0x75Df5AF045d91108662D8080fD1FEFAd6aA0bb59";
const AMB_MAINNET: &str = "0x4C36d2919e407f0Cc2Ee3c993ccF8ac26d9CE64e";

#[derive(Debug, Clone)]
pub enum BridgeSide {
    None,
    Home,
    Foreign,
}

#[derive(Debug, Clone)]
pub struct ChainConfigWithMeta<M> {
    chain_id: u32,
    name: String,
    client: Arc<M>,
    addresses: HashMap<String, H160>,
    bridge_side: BridgeSide,
}

impl<M> ChainConfigWithMeta<M>
where
    M: Middleware + 'static,
{
    /// Create a new chain config, with dynamic address lookup
    /// # Arguments
    /// * `client` - The client to use for the chain
    /// # Returns
    /// * `ChainConfigWithMeta` - The chain config
    pub async fn new(client: Arc<M>) -> Result<Self> {
        let chain_id = client.get_chainid().await.unwrap().as_u64() as u32;
        let mut addresses = HashMap::new();

        // Set the name and bridge side
        let (name, bridge_side) = match chain_id {
            1 => ("mainnet", BridgeSide::Foreign),
            5 => ("goerli", BridgeSide::Foreign),
            100 => ("gnosis", BridgeSide::Home),
            _ => ("unknown", BridgeSide::None),
        };

        // Do dynamic address lookup
        let chainlog = ChainLog::new(H160::from_str(CHAINLOG).unwrap(), client.clone());
        match chain_id {
            1 => {
                let openbzz_address = chainlog
                    .get_address(format_bytes32_string("OPENBZZ_EXCHANGE").unwrap())
                    .await?;

                addresses.insert("OPENBZZ_EXCHANGE".to_string(), openbzz_address);
            }
            100 => {
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

                addresses.insert("POSTAGE_STAMP".to_string(), postage_stamp_address);
                addresses.insert("PRICE_ORACLE".to_string(), price_oracle_address);
                addresses.insert("REDISTRIBUTION".to_string(), redistribution_address);
                addresses.insert("STAKE_REGISTRY".to_string(), stake_registry_address);
            }
            _ => (),
        }

        // Insert static addresses
        match chain_id {
            1 => {
                addresses.insert(
                    "BZZ_ADDRESS_MAINNET".to_string(),
                    BZZ_ADDRESS_MAINNET.parse()?,
                );
                addresses.insert("BONDING_CURVE".to_string(), BONDING_CURVE_MAINNET.parse()?);
                addresses.insert(
                    "DAI_ADDRESS_MAINNET".to_string(),
                    DAI_ADDRESS_MAINNET.parse()?,
                );
                addresses.insert("XDAI_BRIDGE".to_string(), XDAI_BRIDGE_MAINNET.parse()?);
                addresses.insert("OMNI_BRIDGE".to_string(), OMNI_BRIDGE_MAINNET.parse()?);
                addresses.insert("AMB".to_string(), AMB_MAINNET.parse()?);
            }
            5 => todo!(),
            100 => {
                addresses.insert("XDAI_BRIDGE".to_string(), XDAI_BRIDGE_GNOSIS.parse()?);
                addresses.insert("OMNI_BRIDGE".to_string(), OMNI_BRIDGE_GNOSIS.parse()?);
                addresses.insert("AMB".to_string(), AMB_GNOSIS.parse()?);

                // Insert static addresses
                addresses.insert(
                    "BZZ_ADDRESS_GNOSIS".to_string(),
                    BZZ_ADDRESS_GNOSIS.parse()?,
                );
            }
            _ => {}
        }

        Ok(Self {
            chain_id,
            name: name.to_string(),
            client,
            addresses,
            bridge_side,
        })
    }

    pub fn get_address(&self, name: &str) -> Result<H160> {
        Ok(self
            .addresses
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("Address {} not found for chain {}", name, self.name))?)
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

    pub fn bridge_explorer_url(&self, tx_hash: H256) -> (String, String) {
        let tx_hash = format!("0x{}", hex::encode(tx_hash));
        (
            "AMB Monitor".to_string(),
            format!(
                "https://alm-bridge-monitor.gnosischain.com/{}/{}",
                self.chain_id, tx_hash
            ),
        )
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
