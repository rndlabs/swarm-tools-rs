use std::{str::FromStr, sync::Arc};
use eyre::Result;

use crate::contracts::gnosis_proxy_factory::ProxyCreationFilter;
use crate::contracts::{gnosis_proxy_factory::GnosisProxyFactory, gnosis_safe_l2::GnosisSafeL2};
use crate::chain::ChainConfigWithMeta;
use ethers::{prelude::k256::ecdsa::SigningKey, prelude::*};

// Declare constants
const MULTI_SEND_ADDRESS: &str = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761";
const PROXY_FACTORY_ADDRESS: &str = "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2";
const GNOSIS_SAFE_L2_ADDRESS: &str = "0x3E5c63644E683549055b9Be8653de26E0B4CD36E";
const COMPATIBILITY_FALLBACK_HANDLER: &str = "0x017062a1dE2FE6b99BE3d9d37841FeD19F573804";

const FALLBACK_HANDLER_SLOT: &str =
    "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

pub const OPERATION_CALL: u8 = 0;
pub const OPERATION_DELEGATE_CALL: u8 = 1;

// Declare the Safe struct
#[derive(Debug, Clone)]
pub struct Safe<M> {
    pub address: H160,
    pub nonce: U256,
    pub threshold: U256,
    pub owners: Vec<H160>,
    pub master_copy: H160,
    pub fallback_handler: H160,
    pub version: String,
    pub domain_separator: H256,
    pub chain_id: U256,

    pub contract: GnosisSafeL2<M>,
}

// Implement the Safe struct
impl<M> Safe<M> 
where
    M: Middleware,
{
    /// Create a new Safe instance from a list of owners and a threshold
    /// The Safe will be deployed to the L2 network
    pub async fn new(
        owners: Vec<H160>,
        threshold: U256,
        fallback_handler: Option<H160>,
        chain: ChainConfigWithMeta,
        client: Arc<M>,
        wallet: Wallet<SigningKey>,
    ) -> Self {
        let singleton = GnosisSafeL2::new(
            H160::from_str(GNOSIS_SAFE_L2_ADDRESS).unwrap(),
            chain.client()
        );
        let signer = SignerMiddleware::new(
            chain.client(),
            wallet.clone().with_chain_id(chain.chain_id()),
        );
        let contract = GnosisProxyFactory::new(
            H160::from_str(PROXY_FACTORY_ADDRESS).unwrap(),
            signer.into(),
        );

        let cd = singleton
            .setup(
                owners,
                threshold,
                Address::zero(),
                vec![].into(),
                fallback_handler.unwrap_or(H160::from_str(COMPATIBILITY_FALLBACK_HANDLER).unwrap()),
                Address::zero(),
                U256::from(0),
                Address::zero(),
            )
            .calldata()
            .unwrap();

        let handler = crate::wallet::TransactionHandler::new(
            wallet.clone(),
            contract.create_proxy(H160::from_str(GNOSIS_SAFE_L2_ADDRESS).unwrap(), cd),
            "Deploying Safe".to_string(),
        );

        let receipt = handler.handle(&chain, 1).await.unwrap();

        // iterate over the logs to find the ProxyCreated event and get the address of the Safe
        let safe_address = receipt
            .logs
            .iter()
            .find_map(|log| {
                match log.address == H160::from_str(PROXY_FACTORY_ADDRESS).unwrap() {
                    true => {
                        let event = contract
                            .event::<ProxyCreationFilter>()
                            .parse_log(log.clone())
                            .unwrap();
                        Some(event.proxy)
                    }
                    false => None,
                }
            })
            .unwrap();

        Safe::load(safe_address, client.clone()).await
    }

    /// Loads a Safe instance from an address already deployed to the L2 network
    pub async fn load(address: H160, client: Arc<M>) -> Self {
        let safe = GnosisSafeL2::new(address, client.clone());

        // use multicall to get the safe info
        let mut multicall = Multicall::new(client.clone(), None).await.unwrap();
        multicall.add_call(safe.nonce(), false);
        multicall.add_call(safe.get_threshold(), false);
        multicall.add_call(safe.get_owners(), false);
        multicall.add_call(safe.get_storage_at(U256::from(0), U256::from(1)), false);
        multicall.add_call(
            safe.get_storage_at(
                U256::from_str(FALLBACK_HANDLER_SLOT).unwrap(),
                U256::from(1),
            ),
            false,
        );
        multicall.add_call(safe.version(), false);
        multicall.add_call(safe.domain_separator(), false);
        multicall.add_get_chain_id();

        let results: (
            (bool, U256),
            (bool, U256),
            (bool, Vec<H160>),
            (bool, Bytes),
            (bool, Bytes),
            (bool, String),
            (bool, H256),
            (bool, U256),
        ) = multicall.call().await.unwrap();

        let nonce = results.0 .1;
        let threshold = results.1 .1;
        let owners = results.2 .1;
        let master_copy = H160::from_slice(&results.3 .1 .0[12..]);
        let fallback_handler = H160::from_slice(&results.4 .1 .0[12..]);
        let version = results.5 .1;
        let domain_separator = results.6 .1;
        let chain_id = results.7 .1;

        Self {
            address,
            nonce,
            threshold,
            owners,
            master_copy,
            fallback_handler,
            version,
            domain_separator,
            chain_id,
            contract: safe,
        }
    }

    /// Returns the address of the Safe
    /// This is the same as the address of the Safe's proxy contract
    pub fn address(&self) -> H160 {
        self.address
    }

    /// Execute a transaction on the Safe
    /// This will create a Safe transaction and submit it to the Safe
    pub async fn exec_tx(
        &self,
        to: H160,
        value: U256,
        data: Bytes,
        operation: u8,
        description: String,
        chain: ChainConfigWithMeta,
        client: Arc<M>,
        wallet: Wallet<SigningKey>,
        num_confirmations: Option<u8>,
    ) -> Result<TransactionReceipt> {
        // Assert that the operation is valid
        assert!(operation <= 2);
        // Assert that the Safe doesn't have more than 1 owner
        assert!(self.owners.len() == 1);

        // Setup the signer with the given wallet
        let signer = SignerMiddleware::new(
            client.clone(),
            wallet.clone().with_chain_id(chain.chain_id()),
        );
        
        // Connect to the Safe contract
        let contract = GnosisSafeL2::new(self.address, signer.clone().into());

        // As we are using a single owner, we can use the owner's address as the signer
        let mut sig = [0u8; 65];
        sig[0] = 1;
        sig[13..33].copy_from_slice(&signer.address().0);

        let handler = crate::wallet::TransactionHandler::new(
            wallet.clone(),
            contract
            .exec_transaction(
                to,
                value,
                data,
                operation,
                U256::zero(),
                U256::zero(),
                U256::zero(),
                H160::zero(),
                H160::zero(),
                sig.into(),
            ),
            description,
        );
    
        let receipt = handler.handle(&chain, num_confirmations.unwrap_or(1).into()).await?;

        Ok(receipt)
    }
}
