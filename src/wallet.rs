use std::{
    borrow::Borrow,
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use chrono::Utc;
use ethers::{
    abi::Detokenize, prelude::k256::ecdsa::SigningKey, prelude::*, types::H160, utils::format_units,
};
use eyre::{anyhow, Result};
use passwords::PasswordGenerator;

use crate::{
    chain,
    contracts::{
        foreign_omni_bridge::{self, TokensBridgingInitiatedFilter},
        permittable_token::PermittableToken,
    },
    erc20::legacy_permit::Permit,
    exchange,
    game::Game,
    safe::Safe,
    OverlayAddress, WalletArgs, WalletCommands,
};

const CONFIG_DIR: &str = "bees";
const FUNDING_WALLET_KEY: &str = "wallet";
const SAFE_KEY: &str = "safe";

pub async fn process(args: WalletArgs, gnosis_rpc: String) -> Result<()> {
    // Get the config dir and wallet store
    let (config_dir, mut store) = get_cwd_config();
    let gnosis_client = Arc::new(Provider::<Ws>::connect(gnosis_rpc).await?);
    let gnosis_chain = chain::ChainConfigWithMeta::new(gnosis_client.clone()).await?;

    // If the funding wallet doesn't exist, create it
    let funding_wallet = match store.get(FUNDING_WALLET_KEY.to_owned()) {
        Ok(wallet) => wallet,
        Err(_) => {
            println!("Creating funding wallet...");
            let result = store.create_wallet(
                &config_dir,
                None,
                |_key| FUNDING_WALLET_KEY.to_string(),
                |_key| true,
            );

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!(
                    "Funding wallet created: 0x{}",
                    hex::encode(wallet.address())
                );
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
    let safe = match config_dir.join(SAFE_KEY).exists() {
        true => {
            let safe_address =
                H160::from_str(&std::fs::read_to_string(config_dir.join(SAFE_KEY))?)?;

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
            let safe_file = config_dir.join(SAFE_KEY);
            std::fs::write(safe_file, hex::encode(safe.address))?;

            safe
        }
    };

    println!();

    match args.command {
        WalletCommands::SwapAndBridge {
            mainnet_rpc,
            max_bzz,
            xdai,
        } => {
            let mainnet_chain =
                chain::ChainConfigWithMeta::new(Arc::new(Provider::<Ws>::connect(mainnet_rpc).await?))
                    .await?;
            let xdai_per_wallet = xdai.unwrap_or(ethers::utils::WEI_IN_ETHER);

            // Load the game and auto-configure the game's topology
            let game = Game::load(&gnosis_chain, None).await?;

            // Get all the bee node wallets from the store
            // Iterate over them and call permit and approve on the BZZ token
            // for each one
            let wallets = store.get_all();

            // convert wallets to a vector of overlay addresses
            let overlay_addresses = wallets
                .iter()
                .map(|(o, _)| hex::decode(o).unwrap().try_into().unwrap())
                .collect::<Vec<OverlayAddress>>();

            let bzz_funding_table = game.calculate_funding(None, overlay_addresses, max_bzz);

            // iterate over total_funding and print the amount of BZZ
            // and XDAI that needs to be funded for each node
            let mut bzz_req = U256::zero();
            for (o, amount) in bzz_funding_table.iter() {
                bzz_req += *amount;
                println!(
                    "{}: {} BZZ",
                    hex::encode(o),
                    ethers::utils::format_units(*amount, 16)?
                );
            }

            let mut xdai_req = U256::zero();

            // get the xdai balance of each node
            let mut xdai_funding_table: Vec<(OverlayAddress, U256)> = Vec::new();
            // iterate through all the overlays and get their xdai balance
            for (o, _) in bzz_funding_table {
                let xdai_balance = gnosis_client
                    .get_balance(store.get_address(hex::encode(o))?, None)
                    .await?;
                if xdai_balance < xdai_per_wallet {
                    xdai_req += xdai_per_wallet - xdai_balance;
                }
                xdai_funding_table.push((o, xdai_balance));
            }

            // make sure that we include the xdai required for the funding wallet
            let funding_xdai_balance = gnosis_client
                .get_balance(funding_wallet.address(), None)
                .await?;

            if funding_xdai_balance < xdai_per_wallet {
                xdai_req += xdai_per_wallet - funding_xdai_balance;
            }

            println!("Total funding required: {} BZZ", format_units(bzz_req, 16)?);
            println!(
                "Total funding required: {} XDAI",
                format_units(xdai_req, 18)?
            );

            let exchange =
                exchange::Exchange::new(mainnet_chain.clone(), funding_wallet.clone()).await?;
            let dai_funding_required = exchange.quote_gross_buy_amount(bzz_req, None).await?;

            // now include the xDAI that is to be bridged as well
            let dai_funding_required = dai_funding_required + xdai_req;

            println!(
                "Total DAI funding required for buying BZZ: {} DAI",
                format_units(dai_funding_required, 18)?
            );

            let f_omni_bridge = foreign_omni_bridge::ForeignOmniBridge::new(
                mainnet_chain.get_address("OMNI_BRIDGE").unwrap(),
                mainnet_chain.client(),
            );

            let receipt = exchange
                .buy_and_bridge_bzz(bzz_req, None, Some(safe.address()))
                .await?;

            // iterate over the logs to find the ProxyCreated event and get the address of the Safe
            let bzz_bridging = receipt
                .logs
                .iter()
                .find_map(|log| match log.address == f_omni_bridge.address() {
                    true => {
                        let e = ethers::contract::parse_log::<TokensBridgingInitiatedFilter>(
                            log.clone(),
                        )
                        .unwrap();
                        Some(e)
                    }
                    false => None,
                })
                .unwrap();

            // bzz_bridging.message_id - this is the message id of the bridging transaction

            assert_eq!(
                bzz_bridging.token,
                mainnet_chain.get_address("BZZ_ADDRESS_MAINNET")?
            );
            assert_eq!(bzz_bridging.value, bzz_req);

            // 1. Calculate how much xDAI and BZZ is need for the nodes.
            // 2. Bridge the required xDAI from the mainnet DAI to the gnosis chain xDAI (funding wallet recipient).
            // 3. Swap mainnet DAI for the required BZZ and bridge it to gnosis chain BZZ (`safe` receipient).
            // 4. Watch for `AffirmationCompleted(address recipient, uint256 value, bytes32 transactionHash)` to monitor
            //    the progress of bridging (2). The transaction hash is the hash of the transaction that was bridged in (2).
            // 5. Watch for `AffirmationCompleted (index_topic_1 address sender, index_topic_2 address executor, index_topic_3 bytes32 messageId, bool status)`
            //    to monitor the progress of bridging (3). The message id is the message id of the message in the `UserRequestForSignature` event
            //    on the foreign side.
            // 6. Once the `AffirmationCompleted` event is seen for (2) and (3), execute an arbitrary closure.

            // println!("{:#?}", receipt);

            Ok(())
        }
        WalletCommands::DistributeFunds {
            max_bzz: _,
            xdai: _,
        } => {
            todo!()
        }
        WalletCommands::PermitApproveAll { token } => {
            let contract = PermittableToken::new(
                token.unwrap_or(gnosis_chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap()),
                gnosis_client.clone(),
            );

            // Get all the bee node wallets from the store
            // Iterate over them and call permit and approve on the BZZ token
            // for each one
            let wallets = store.get_all();

            let mut permits: Vec<Bytes> = Vec::new();

            let mut description =
                "Permit and approve Safe to spend BZZ tokens on behalf of nodes:".to_string();
            let staking_registry_address = gnosis_chain.get_address("STAKE_REGISTRY").unwrap();

            for (name, wallet) in wallets {
                description = format!("{}\n - {}", description, name);

                // First do the permit for the Safe to spend the BZZ tokens
                let permit = Permit::new(
                    wallet.address(),
                    safe.address(),
                    None,
                    U256::from(Utc::now().timestamp() as u32 + 60 * 30),
                    true,
                    gnosis_client.clone(),
                    contract.address(),
                )
                .await
                .unwrap();

                let signature = permit
                    .sign(
                        wallet.clone(),
                        gnosis_client.clone(),
                        contract.address(),
                        None,
                    )
                    .await?;
                permits.push(
                    permit
                        .permit_calldata(signature, gnosis_client.clone(), contract.address())
                        .await?,
                );

                // if the token is BZZ, we need to also permit and approve the staking registry
                if token.is_none() {
                    // Next do the permit for the stake registry to spend the BZZ tokens
                    let permit = Permit::new(
                        wallet.address(),
                        staking_registry_address,
                        Some(1.into()),
                        U256::from(Utc::now().timestamp() as u32 + 60 * 30),
                        true,
                        gnosis_client.clone(),
                        contract.address(),
                    )
                    .await
                    .unwrap();

                    let signature = permit
                        .sign(wallet, gnosis_client.clone(), contract.address(), None)
                        .await?;
                    permits.push(
                        permit
                            .permit_calldata(signature, gnosis_client.clone(), contract.address())
                            .await?,
                    );
                }
            }

            let mut txs = Vec::new();
            for permit in permits {
                txs.push((
                    crate::safe::OPERATION_CALL,
                    contract.address(),
                    U256::from(0),
                    permit,
                ));
            }

            let _receipt = safe
                .exec_batch_tx(
                    txs,
                    description,
                    gnosis_chain,
                    gnosis_client,
                    funding_wallet,
                    1.into(),
                )
                .await?;

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

            let mut multicall =
                Multicall::<Provider<Ws>>::new(gnosis_chain.client(), None).await?;

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
                // TODO: if *balance > 0.into() {
                let wallet = &wallets[i].1;
                let transfer = contract.transfer_from(wallet.address(), safe.address(), *balance);
                txs.push(transfer.calldata().unwrap());
                description = format!(
                    "{}\n - {} ({})",
                    description,
                    wallets[i].0,
                    format_units(*balance, 16)?
                );
                // }
            }

            let _receipt = safe
                .exec_batch_tx(
                    txs.into_iter()
                        .map(|tx| {
                            (
                                crate::safe::OPERATION_CALL,
                                contract.address(),
                                U256::from(0),
                                tx,
                            )
                        })
                        .collect(),
                    description,
                    gnosis_chain,
                    gnosis_client,
                    funding_wallet,
                    1.into(),
                )
                .await?;

            Ok(())
        }
        WalletCommands::StakeAll => {
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
    where
        M: Middleware + Clone + 'static,
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
                format_units(gas_cost, "ether")?,
                chain.native_units()
            );
            std::process::exit(1);
        }

        // Display the transaction details
        println!("{}:", self.description);
        // blank line
        println!();
        println!("Transaction Details:");
        println!("  From: 0x{}", hex::encode(self.wallet.address()));
        println!(
            "  To: 0x{}",
            hex::encode(self.call.tx.to().unwrap().as_address().unwrap())
        );
        println!("  Value: {}", self.call.tx.value().unwrap_or(&U256::zero()));
        println!("  Data: 0x{}", hex::encode(self.call.tx.data().unwrap()));
        println!("  Gas Limit: {}", gas_limit);
        println!("  Gas Price: {}", format_units(gas_price, "gwei")?);
        println!("  Gas Cost: {}", format_units(gas_cost, "ether")?);
        println!();

        // Confirm with the user that they want to send the transaction
        let mut input = String::new();
        print!("Send transaction? [y/N]: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut input)?;
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
        let receipt = tx.confirmations(num_confirmations).await?.unwrap();

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

    pub fn remove_wallet(&mut self, name: String) -> Result<()> {
        if !self.wallets.contains_key(&name) {
            return Err(anyhow!("Wallet not found"));
        }

        self.wallets.remove(&name);
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

        let keystore_path = path.join(uuid);
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
        self.insert_wallet(name, wallet.clone())?;

        // return the path to the keystore and the password
        Ok((wallet, password))
    }
}

/// Get the default configuration directory and the wallet store
fn get_cwd_config() -> (PathBuf, WalletStore) {
    let path = PathBuf::from(".");
    let store_dir = path.join(CONFIG_DIR);

    let store = WalletStore::load(store_dir.clone()).unwrap();

    (store_dir, store)
}
