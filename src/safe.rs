use eyre::Result;
use std::{str::FromStr, sync::Arc};

use crate::chain::ChainConfigWithMeta;
use crate::contracts::gnosis_proxy_factory::ProxyCreationFilter;
use crate::contracts::multi_send::MultiSend;
use crate::contracts::{gnosis_proxy_factory::GnosisProxyFactory, gnosis_safe_l2::GnosisSafeL2};
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
    M: Middleware + 'static,
{
    /// Create a new Safe instance from a list of owners and a threshold
    /// The Safe will be deployed to the L2 network
    pub async fn new(
        owners: Vec<H160>,
        threshold: U256,
        fallback_handler: Option<H160>,
        chain: ChainConfigWithMeta<M>,
        client: Arc<M>,
        wallet: Wallet<SigningKey>,
    ) -> Self {
        let singleton = GnosisSafeL2::new(
            H160::from_str(GNOSIS_SAFE_L2_ADDRESS).unwrap(),
            client.clone(),
        );
        let signer = SignerMiddleware::new(
            client.clone(),
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

        let handler = crate::wallet::CliTransactionHandler::new(
            wallet.clone(),
            contract.create_proxy(H160::from_str(GNOSIS_SAFE_L2_ADDRESS).unwrap(), cd),
            "Deploying Safe".to_string(),
        );

        let receipt = handler.handle(&chain, 1).await.unwrap();

        // iterate over the logs to find the ProxyCreated event and get the address of the Safe
        let safe_address = receipt
            .logs
            .iter()
            .find_map(
                |log| match log.address == H160::from_str(PROXY_FACTORY_ADDRESS).unwrap() {
                    true => {
                        let e = ethers::contract::parse_log::<ProxyCreationFilter>(log.clone())
                            .unwrap();
                        Some(e.proxy)
                    }
                    false => None,
                },
            )
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

        let results: (U256, U256, Vec<H160>, Bytes, Bytes, String, H256, U256) =
            multicall.call().await.unwrap();

        let nonce = results.0;
        let threshold = results.1;
        let owners = results.2;
        let master_copy = H160::from_slice(&results.3 .0[12..]);
        let fallback_handler = H160::from_slice(&results.4 .0[12..]);
        let version = results.5;
        let domain_separator = results.6;
        let chain_id = results.7;

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

    /// Execute a batch of transactions on the Safe using the Mulitsend contract
    /// This will create a Safe transaction and submit it to the Safe
    pub async fn exec_batch_tx(
        &self,
        batch: Vec<(u8, H160, U256, Bytes)>,
        description: String,
        chain: ChainConfigWithMeta<M>,
        client: Arc<M>,
        wallet: Wallet<SigningKey>,
        num_confirmations: Option<u8>,
    ) -> Result<TransactionReceipt> {
        // Assert that the Safe doesn't have more than 1 owner
        assert!(self.owners.len() == 1);

        // Setup the signer with the given wallet
        let signer = SignerMiddleware::new(
            client.clone(),
            wallet.clone().with_chain_id(chain.chain_id()),
        );

        let mut tx_multisends: Vec<Vec<u8>> = Vec::new();
        for (operation, to, value, data) in batch {
            // Assert that the operation is valid
            assert!(operation <= 2);

            let mut call: Vec<u8> = Vec::new();
            let mut value_raw = [0u8; 32];
            value.to_big_endian(&mut value_raw);

            let mut data_length_raw = [0u8; 32];
            U256::from(data.len()).to_big_endian(&mut data_length_raw);

            // use solidity abi packed encoding to encode the transaction
            call.push(operation);
            call.extend_from_slice(to.as_bytes());
            call.extend_from_slice(&value_raw);
            call.extend_from_slice(&data_length_raw);
            call.extend_from_slice(data.as_ref());

            tx_multisends.push(call);
        }

        // reduce the tx_multisends to a single vector
        let txs: Vec<u8> = tx_multisends.into_iter().flatten().collect();

        let contract = MultiSend::new(H160::from_str(MULTI_SEND_ADDRESS).unwrap(), signer.into());

        let call = contract.multi_send(txs.into());
        let data = call.calldata().unwrap();

        Ok(self
            .exec_tx(
                H160::from_str(MULTI_SEND_ADDRESS)?,
                U256::zero(),
                data,
                OPERATION_DELEGATE_CALL,
                description,
                chain,
                client,
                wallet,
                num_confirmations,
            )
            .await?)
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
        chain: ChainConfigWithMeta<M>,
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
        // set the first 32 bytes to the address
        sig[12..32].copy_from_slice(&self.owners[0].0);
        sig[64] = 1;

        let signatures = Bytes::from(sig);

        let handler = crate::wallet::CliTransactionHandler::new(
            wallet.clone(),
            contract.exec_transaction(
                to,
                value,
                data,
                operation,
                U256::zero(),
                U256::zero(),
                U256::zero(),
                H160::zero(),
                H160::zero(),
                signatures,
            ),
            description,
        );

        let receipt = handler
            .handle(&chain, num_confirmations.unwrap_or(1).into())
            .await?;

        Ok(receipt)
    }
}
