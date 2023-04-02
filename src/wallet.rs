use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc, borrow::Borrow,
};

use ethers::{
    abi::Detokenize,
    prelude::k256::ecdsa::SigningKey,
    prelude::*,
    types::transaction::eip712::{EIP712Domain, EIP712WithDomain, Eip712},
    types::H160,
};
use eyre::{anyhow, Result};
use passwords::PasswordGenerator;

use crate::{
    chain, contracts::permittable_token::PermittableToken, safe::Safe, WalletArgs, WalletCommands,
};

const DEFAULT_CONFIG_DIR: &str = "bees";

pub async fn process(args: WalletArgs, gnosis_rpc: String) -> Result<()> {
    // Get the config dir and wallet store
    let (config_dir, mut store) = get_cwd_config();
    let gnosis_client = Arc::new(Provider::<Http>::try_from(gnosis_rpc)?);
    let gnosis_chain = chain::ChainConfigWithMeta::new(gnosis_client.clone()).await?;

    // If the funding wallet doesn't exist, create it
    let funding_wallet = match store.get(FUNDING_WALLET_KEY.to_owned()) {
        Ok(wallet) => wallet,
        Err(_) => {
            println!("Creating funding wallet...");
            let result =
                store.create_wallet(&config_dir, None, |_key| FUNDING_WALLET_KEY.to_string(), |_key| true);

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!("Funding wallet created: 0x{}", hex::encode(wallet.address()));
                println!("Password: {}", password);
            }
            println!();

            let funding_wallet = store.get(FUNDING_WALLET_KEY.to_owned()).unwrap();

            // Use a loop for checking if the user has requested xDAI
            loop {
                // Check if the funding wallet has any xDAI
                let balance = gnosis_client
                    .get_balance(funding_wallet.address(), None)
                    .await?;

                // If the balance is greater than 0.0025, break out of the loop
                match balance > ethers::utils::parse_ether("0.0025")? {
                    true => break,
                    false => {
                        println!("Please visit https://gnosisfaucet.com/ and request some xDAI for the funding wallet. Then press enter to continue...");
                        let mut input = String::new();
                        // Wait for the user to press enter
                        std::io::stdin().read_line(&mut input)?;
                    }
                }

            }

            funding_wallet
        }
    };

    // Remove the funding wallet from the store
    store.remove_wallet(FUNDING_WALLET_KEY.to_string())?;

    // Get the safe address from the config directory
    let safe = match config_dir.join(SAFE_KEY.to_string()).exists() {
        true => {
            let safe_address = H160::from_str(&std::fs::read_to_string(config_dir.join(SAFE_KEY.to_string()))?)?;

            println!("Loading Safe 0x{}...", hex::encode(safe_address));

            let safe = Safe::load(safe_address, gnosis_client.clone()).await;

            // Check to make sure the funding_wallet is an owner of the safe
            if !safe.is_owner(funding_wallet.address()) {
                return Err(anyhow!("Funding wallet is not an owner of the Safe"));
            }

            safe
        }
        false => {
            println!("Creating Safe...");
            let safe = Safe::new(
                vec![funding_wallet.address()],
                1.into(),
                None,
                gnosis_chain.clone(),
                gnosis_client.clone(),
                funding_wallet.clone(),
            )
            .await;

            println!("Safe created: gno:0x{}", hex::encode(safe.address));

            // Save the safe's address to a file in the config directory
            let safe_file = config_dir.join(SAFE_KEY.to_string());
            std::fs::write(safe_file, hex::encode(safe.address))?;

            safe
        }
    };

        WalletCommands::SwapAndBridge {
            mainnet_rpc,
            max_bzz,
            xdai,
        } => {
            todo!()
        }
        WalletCommands::DistributeFunds { max_bzz, xdai } => {
            todo!()
        }
        WalletCommands::PermitApproveAll { token } => {
            let contract =
                PermittableToken::new(token.unwrap_or(gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap()), gnosis_client.clone());

            // Get all the bee node wallets from the store
            // Iterate over them and call permit and approve on the BZZ token
            // for each one
            let wallets = store.get_all();

            let mut permits: Vec<Bytes> = Vec::new();

            let mut description = "Permit and approve Safe to spend BZZ tokens on behalf of nodes:".to_string();

            for (name, wallet) in wallets {
                description = format!("{}\n - {}", description, name);
                permits.push(
                    legacy_permit_approve(
                        wallet.clone(),
                        contract.address(),
                        funding_wallet.address(),
                        None,
                        client.clone(),
                    )
                    .await?,
                );

                // if the token is BZZ, we need to also permit and approve the staking registry
                if token.is_none() {
                    let staking_registry_address = chain.get_address("STAKE_REGISTRY").unwrap();
                    permits.push(
                        legacy_permit_approve(
                            wallet,
                            contract.address(),
                            staking_registry_address,
                            Some(1.into()),
                            client.clone(),
                        )
                        .await?,
                    );
                }
            }

            // Load the safe
            let safe_file = config_dir.join("safe");
            let safe_address = hex::decode(std::fs::read_to_string(safe_file)?)?;
            let safe = Safe::load(H160::from_slice(&safe_address), client.clone()).await;

            let mut txs = Vec::new();
            for permit in permits {
                txs.push((
                    crate::safe::OPERATION_CALL,
                    contract.address(),
                    U256::from(0),
                    permit,
                ));
            }

            let receipt = safe
                .exec_batch_tx(
                    txs,
                    description,
                    gnosis_chain,
                    gnosis_client,
                    funding_wallet,
                    1.into(),
                )
                .await?;

            println!("Safe tx hash: {:?}", receipt);

            Ok(())
        }
        WalletCommands::SweepAll { token } => {
            // Connect to the BZZ token contract
            let contract = PermittableToken::new(
                token.unwrap_or(gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS")?),
                gnosis_client.clone(),
            );

            // Get all the bee node wallets from the store
            // iterate over them and call transfer on the BZZ token for each one
            let wallets = store.get_all();

            let mut multicall = Multicall::<Provider<Http>>::new(gnosis_chain.client(), None).await?;

            // iterate through the wallets and get their balances
            for (_, wallet) in wallets.iter() {
                multicall.add_call(contract.balance_of(wallet.address()), false);
            }
            let balances: Vec<U256> = multicall.call_array().await?;

            let mut description = "Sweeping funds from nodes to Safe:".to_string();
            let mut txs: Vec<Bytes> = Vec::new();
            // balances and wallets are in the same order
            // iterate over the wallets, and if the balance is greater than 0 use transferFrom to
            // transfer the balance to the safe
            for (i, balance) in balances.iter().enumerate() {
                // if *balance > 0.into() {
                    let wallet = &wallets[i].1;
                    let transfer = contract.transfer_from(
                        wallet.address(),
                        safe.address(),
                        *balance,
                    );
                    txs.push(transfer.calldata().unwrap());
                    description = format!("{}\n - {} ({})", description, wallets[i].0, ethers::utils::format_units(*balance, 16).unwrap());
                // }
            }
            
            let receipt = safe
                .exec_batch_tx(
                    txs.into_iter().map(|tx| (crate::safe::OPERATION_CALL, contract.address(), U256::from(0), tx)).collect(),
                    description,
                    gnosis_chain,
                    gnosis_client,
                    funding_wallet,
                    1.into(),
                )
                .await?;

            Ok(())
        }
        WalletCommands::StakeAll { rpc } => {
            todo!()
        }
    }
}

/// A transaction handler for sending transactions
pub struct CliTransactionHandler<B, M, D, S>
where
    B: Borrow<SignerMiddleware<Arc<M>, S>> + Clone,
    M: Middleware + 'static,
    D: Detokenize,
    S: Signer,
{
    wallet: Wallet<SigningKey>,
    call: FunctionCall<B, SignerMiddleware<Arc<M>, S>, D>,
    description: String,
}

impl<B, M, D, S> CliTransactionHandler<B, M, D, S>
where
    B: Borrow<SignerMiddleware<Arc<M>, S>> + Clone,
    M: Middleware + 'static,
    D: Detokenize,
    S: Signer,
{
    /// Create a new transaction handler
    pub fn new(
        wallet: Wallet<SigningKey>,
        call: FunctionCall<B, SignerMiddleware<Arc<M>, S>, D>,
        description: String,
    ) -> Self {
        Self {
            wallet,
            call,
            description,
        }
    }

    /// Handle the CLI prompt for sending a transaction
    pub async fn handle(
        &self,
        chain: &chain::ChainConfigWithMeta<M>,
        num_confirmations: usize,
    ) -> Result<TransactionReceipt> 
        where M: Middleware + 'static,
    {
        let client = chain.client();

        // Get the gas estimate and gas price
        let gas_limit = match self.call.estimate_gas().await {
            Ok(gas_limit) => gas_limit,
            Err(err) => {
                println!("Error estimating gas: {}", err);
                std::process::exit(1);
            }
        };
        let gas_price = client.get_gas_price().await?;

        // Calculate the total gas cost
        let gas_cost = gas_limit * gas_price;

        // Get the balance of the wallet
        let balance = client.get_balance(self.wallet.address(), None).await?;

        // If the balance is less than gas cost, print an error and return
        // Tell them how much to fund the wallet with
        if balance < gas_cost {
            println!(
                "Insufficient funds to send transaction. Please fund the wallet with at least {} {}",
                ethers::utils::format_units(gas_cost, "ether").unwrap(),
                chain.native_units()
            );
            std::process::exit(1);
        }

        // Display the transaction details
        println!("{}:", self.description);
        println!("Transactoion Details:");
        println!("  From: 0x{}", hex::encode(self.wallet.address()));
        println!(
            "  To: 0x{}",
            hex::encode(self.call.tx.to().unwrap().as_address().unwrap())
        );
        println!("  Value: {}", self.call.tx.value().unwrap_or(&U256::zero()));
        println!("  Data: 0x{}", hex::encode(self.call.tx.data().unwrap()));
        println!("  Gas Limit: {}", gas_limit);
        println!(
            "  Gas Price: {}",
            ethers::utils::format_units(gas_price, "gwei").unwrap()
        );
        println!(
            "  Gas Cost: {}",
            ethers::utils::format_units(gas_cost, "ether").unwrap()
        );
        println!("");

        // Confirm with the user that they want to send the transaction
        let mut input = String::new();
        print!("Send transaction? [y/N]: ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut input).unwrap();
        if input.trim().to_lowercase() != "y" {
            std::process::exit(0);
        }

        // Set the gas limit and gas price
        // This is done after the confirmation prompt so that the user can see the gas cost
        // dev: we clone the call here because we're mutating it
        let call = self.call.clone().gas(gas_limit).gas_price(gas_price);

        // Send the transaction
        let tx = call.send().await;

        // If the transaction failed to send, print an error and return
        if let Err(err) = tx {
            // if the error message contains "insufficient funds", print a more helpful message
            if err.to_string().contains("insufficient funds") {
                println!("Insufficient funds to send transaction. Please fund the wallet with at least {} {}", ethers::utils::format_units(gas_cost, "ether").unwrap(), chain.native_units());
            } else {
                println!("Error sending transaction: {}", err);
            }
            std::process::exit(1);
        }

        // Get the transaction hash
        let tx = tx.unwrap();

        // Print the URL to the transaction on the block explorer
        let (explorer, url) = chain.explorer_url(tx.tx_hash());

        // Print URL to the transaction on the block explorer
        println!("Submitting the transaction to {}: {}", explorer, url);

        // Waiting for the transaction to be mined
        print!(
            "Waiting for the transaction to be mined (waiting for {} confirmations)...",
            num_confirmations
        );
        let receipt = tx.confirmations(num_confirmations).await.unwrap().unwrap();

        // if the transaction failed, print an error and return
        if receipt.status == Some(0.into()) {
            println!("Transaction failed. See the transaction on the block explorer for more details: {}", url);
            std::process::exit(1);
        }
        
        // If we made it this far, the transaction was successful
        println!("successful!");

        Ok(receipt)
    }
}

/// A wallet store
/// This is a collection of wallets that can be used to sign transactions
pub struct WalletStore {
    path: PathBuf,
    wallets: HashMap<String, Wallet<SigningKey>>,
    pg: PasswordGenerator,
}

impl WalletStore {
    /// Load a wallet store from the given path
    pub fn load(path: PathBuf) -> Result<Self> {
        // The path should be a directory
        if !path.is_dir() {
            // create the directory if it doesn't exist
            std::fs::create_dir_all(path.clone()).unwrap();
        }

        // Create a new wallet store
        let mut store = Self {
            path: path.clone(),
            wallets: HashMap::new(),
            pg: PasswordGenerator {
                length: 32,
                numbers: true,
                lowercase_letters: true,
                uppercase_letters: true,
                symbols: false,
                spaces: false,
                exclude_similar_characters: true,
                strict: true,
            },
        };

        // Iterate over all the files in the directory. Any .json files are assumed to be keystore files
        for entry in path.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().unwrap_or_default() == "json" {
                store.load_wallet(&path)?;
            }
        }

        Ok(store)
    }

    /// Load a wallet from a keystore file
    /// The password is assumed to be in a file with the same name as the keystore but with a .password extension
    /// The wallet name is assumed to be the file name without the extension
    pub fn load_wallet(&mut self, path: &Path) -> Result<()> {
        // We assume that the path is a file to the encrypted keystore
        if !path.is_file() {
            return Err(anyhow!("Invalid keystore path"));
        }

        // The password to load the keystore is in the file with the same name as the keystore but with a .password extension
        let password_path = path.with_extension("password");
        if !password_path.is_file() {
            return Err(anyhow!("Password file not found"));
        }

        // Load the password from the file
        std::fs::read_to_string(password_path)
            .map_err(|e| anyhow!("Failed to read password file: {}", e))
            .and_then(|password| {
                // Load the wallet from the keystore
                let wallet = LocalWallet::decrypt_keystore(path, password)?;
                // Get the wallet name from the file name (strip the extension)
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();

                println!("Loaded wallet: {}", name);

                // Add the wallet to the store
                self.wallets.insert(name, wallet);
                Ok(())
            })
    }

    /// Insert a wallet into the store
    pub fn insert_wallet(&mut self, name: String, wallet: Wallet<SigningKey>) -> Result<()> {
        if self.wallets.contains_key(&name) {
            return Err(anyhow!("Wallet already exists"));
        }

        self.wallets.insert(name, wallet);
        Ok(())
    }

    /// Get a wallet by its name
    pub fn get(&self, name: String) -> Result<Wallet<SigningKey>> {
        match self.wallets.get(&name) {
            Some(wallet) => Ok(wallet.clone()),
            None => Err(anyhow!("Wallet not found")),
        }
    }

    /// Get the address of a wallet by its name
    pub fn get_address(&self, name: String) -> Result<H160> {
        self.get(name).map(|wallet| wallet.address())
    }

    /// Get the name of a wallet by its address
    pub fn get_name(&self, address: H160) -> Result<String> {
        for (name, wallet) in self.wallets.iter() {
            if wallet.address() == address {
                return Ok(name.clone());
            }
        }

        Err(anyhow!("Wallet not found"))
    }

    /// Get all the wallets in the store
    /// This returns a vector of tuples containing the wallet name and the wallet
    /// The wallets are sorted by name
    pub fn get_all(&self) -> Vec<(String, Wallet<SigningKey>)> {
        let mut wallets: Vec<(String, Wallet<SigningKey>)> = self
            .wallets
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        wallets.sort_by(|a, b| a.0.cmp(&b.0));
        wallets
    }

    /// Create a new wallet
    /// If the password is not provided, a random one will be generated
    /// The name of the wallet will be generated by the name function
    /// The wallet will be verified by the verify function
    /// If the wallet is not verified, the wallet will not be created
    /// The wallet will be saved to the path provided
    pub fn create_wallet<F, N>(
        &mut self,
        path: &Path,
        password: Option<String>,
        name: N,
        verify: F,
    ) -> Result<(Wallet<SigningKey>, String)>
    where
        F: FnOnce(Wallet<SigningKey>) -> bool,
        N: FnOnce(Wallet<SigningKey>) -> String,
    {
        // If the password is not provided, generate a random one
        let password = match password {
            Some(password) => password,
            None => self.pg.generate_one().unwrap(),
        };

        // create a new keystore with the password
        let (wallet, uuid) =
            LocalWallet::new_keystore(path, &mut rand::thread_rng(), password.clone(), None)?;

        // Verify the wallet
        if !verify(wallet.clone()) {
            return Err(anyhow!("Wallet verification failed"));
        }

        // Get the name of the wallet
        let name = name(wallet.clone());

        let keystore_path = path.join(format!("{}", uuid));
        let new_keystore_path = self.path.join(format!("{}.json", name));
        println!(
            "{} -> {}",
            keystore_path.display(),
            new_keystore_path.display()
        );
        std::fs::copy(keystore_path, new_keystore_path)?;

        // Save the password to the wallet store path
        let password_path = self.path.join(format!("{}.password", name));
        std::fs::write(password_path, password.clone())?;

        // Add the wallet to the wallet store
        self.insert_wallet(name.clone(), wallet.clone())?;

        // return the path to the keystore and the password
        Ok((wallet, password))
    }
}

/// Get the default configuration directory and the wallet store
fn get_cwd_config() -> (PathBuf, WalletStore) {
    let path = PathBuf::from(".");
    let store_dir = path.join(DEFAULT_CONFIG_DIR);

    let store = WalletStore::load(store_dir.clone()).unwrap();

    (store_dir, store)
}
