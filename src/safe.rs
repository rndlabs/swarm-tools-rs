use std::{str::FromStr, sync::Arc};

use crate::chain::Chain;
use crate::contracts::gnosis_proxy_factory::ProxyCreationFilter;
use crate::contracts::{gnosis_proxy_factory::GnosisProxyFactory, gnosis_safe_l2::GnosisSafeL2};
use ethers::{prelude::k256::ecdsa::SigningKey, prelude::*};

// Declare constants
const MULTI_SEND_ADDRESS: &str = "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761";
const PROXY_FACTORY_ADDRESS: &str = "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2";
const GNOSIS_SAFE_L2_ADDRESS: &str = "0x3E5c63644E683549055b9Be8653de26E0B4CD36E";
const COMPATIBILITY_FALLBACK_HANDLER: &str = "0x017062a1dE2FE6b99BE3d9d37841FeD19F573804";

const FALLBACK_HANDLER_SLOT: &str =
    "0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5";

// Declare the Safe struct
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Safe {
    pub address: H160,
    pub nonce: U256,
    pub threshold: U256,
    pub owners: Vec<H160>,
    pub master_copy: H160,
    pub fallback_handler: H160,
    pub version: String,
    pub domain_separator: H256,
    pub chain_id: U256,
}

// Implement the Safe struct
impl Safe {
    /// Create a new Safe instance from a list of owners and a threshold
    /// The Safe will be deployed to the L2 network
    pub async fn new(
        owners: Vec<H160>,
        threshold: U256,
        fallback_handler: Option<H160>,
        chain: &Chain,
        wallet: Wallet<SigningKey>,
    ) -> Self {
        let client = chain.client();

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

        let call = contract.create_proxy(H160::from_str(GNOSIS_SAFE_L2_ADDRESS).unwrap(), cd);

        // Estimate the gas limit
        let gas_limit = client.estimate_gas(&call.tx, None).await.unwrap();

        // Estimate the gas price
        let gas_price = client.get_gas_price().await.unwrap();

        // Confirm with the user
        println!("Gas limit: {}", gas_limit);
        println!("Gas price: {}", gas_price);
        println!(
            "Total gas cost: {} xDAI",
            ethers::utils::format_units(gas_limit * gas_price, "ether").unwrap()
        );

        // Make sure the user has enough funds. If not, print a helpful message with how much they need
        let balance = client.get_balance(wallet.address(), None).await.unwrap();
        if balance < gas_limit * gas_price {
            println!("Your wallet 0x{} has insufficient funds. You have {} xDAI, but you need at least {} xDAI to deploy a Safe.", hex::encode(wallet.address()), ethers::utils::format_units(balance, "ether").unwrap(), ethers::utils::format_units(gas_limit * gas_price, "ether").unwrap());
            println!("You can get xDAI from a faucet: https://gnosisfaucet.com/");
            // exit the program without panicking
            std::process::exit(1);
        }

        // Prompt the user to confirm
        println!("Do you want to continue? [y/n]");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim() != "y" {
            panic!("Aborted");
        }

        // Set the gas limit and gas price
        let call = call.gas(gas_limit).gas_price(gas_price);

        // Send the transaction
        let tx = call.send().await;

        // If the transaction failed, print the error
        if let Err(e) = tx {
            // if the error message contains "insufficient funds", print a more helpful message
            if e.to_string().contains("insufficient funds") {
                println!(
                    "Transaction failed: insufficient funds. Please check your wallet balance."
                );
            } else {
                println!("Transaction failed: {:?}", e);
            }
            panic!("Aborted");
        }

        // Get the transaction hash
        let tx = tx.unwrap();

        // Print URL for Gnosisscan
        println!(
            "Submitting the transaction to Gnosis Chain... https://gnosisscan.io/tx/0x{}",
            hex::encode(tx.tx_hash())
        );
        println!("Waiting for the transaction to be mined...");

        // Wait for the transaction to be mined
        let receipt = tx.confirmations(1).await.unwrap().unwrap();

        // iterate over the logs to find the ProxyCreated event and get the address of the Safe
        let safe_address = receipt
            .logs
            .iter()
            .find_map(|log| {
                if log.address == H160::from_str(PROXY_FACTORY_ADDRESS).unwrap() {
                    let event = contract
                        .event::<ProxyCreationFilter>()
                        .parse_log(log.clone())
                        .unwrap();
                    Some(event.proxy)
                } else {
                    None
                }
            })
            .unwrap();

        println!("Safe deployed at: {}", safe_address);

        Safe::load(safe_address, client).await
    }

    /// Loads a Safe instance from an address already deployed to the L2 network
    pub async fn load(address: H160, client: Arc<Provider<Http>>) -> Self {
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
        }
    }
}
