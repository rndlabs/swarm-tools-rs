use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use ethers::{
    abi::Detokenize,
    prelude::k256::ecdsa::SigningKey,
    prelude::{builders::ContractCall, *},
    types::transaction::eip712::{EIP712Domain, EIP712WithDomain, Eip712},
    types::H160,
};
use eyre::{anyhow, Result};
use passwords::PasswordGenerator;

use crate::{
    chain, contracts::permittable_token::PermittableToken, safe::Safe, WalletArgs, WalletCommands,
};

const DEFAULT_CONFIG_DIR: &str = "bees";

pub async fn process(args: WalletArgs) -> Result<()> {
    // Get the config dir and wallet store
    let (config_dir, mut store) = get_cwd_config();
    match args.command {
        WalletCommands::Generate => {
            if store.get("wallet".to_owned()).is_ok() {
                return Err(anyhow!("Wallet already exists"));
            }

            // Wallet doesn't exist, so create a new one
            let result =
                store.create_wallet(&config_dir, None, |_key| "wallet".to_string(), |_key| true);

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!("Wallet created: 0x{}", hex::encode(wallet.address()));
                println!("Password: {}", password);
            }

            Ok(())
        }
        WalletCommands::InitSafe { rpc } => {
            let funding_wallet = store.get("wallet".to_owned()).unwrap();

            // Determine if the Safe has already been created
            if config_dir.join("safe").exists() {
                return Err(anyhow!("Safe already exists"));
            }

            let chain = chain::ChainConfigWithMeta::new(rpc).await?;
            let client = chain.client();

            // Create the Safe
            let safe = Safe::new(
                vec![funding_wallet.address()],
                1.into(),
                None,
                chain,
                client,
                funding_wallet,
            )
            .await;

            println!("Safe created: 0x{}", hex::encode(safe.address));

            // Save the safe's address to a file in the config directory
            let safe_file = config_dir.join("safe");
            std::fs::write(safe_file, hex::encode(safe.address))?;

            Ok(())
        }
        WalletCommands::SwapAndBridge {
            mainnet_rpc,
            gnosis_rpc,
            max_bzz,
            xdai,
        } => {
            todo!()
        }
        WalletCommands::DistributeFunds { max_bzz, xdai, rpc } => {
            todo!()
        }
        WalletCommands::PermitApproveAll {
            token,
            rpc,
        } => {
            let funding_wallet = store.get("wallet".to_owned()).unwrap();
            let chain = chain::ChainConfigWithMeta::new(rpc).await?;
            let client = chain.client();

            let contract =
                PermittableToken::new(token.unwrap_or(chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap()), client.clone());

            // Get all the bee node wallets from the store
            // Iterate over them and call permit and approve on the BZZ token
            // for each one
            let wallets = store.get_all();

            // filter out the funding wallet
            let wallets = wallets
                .into_iter()
                .filter(|(name, _)| name != "wallet")
                .collect::<HashMap<String, Wallet<SigningKey>>>();

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
                    chain,
                    client,
                    funding_wallet,
                    1.into(),
                )
                .await?;

            println!("Safe tx hash: {:?}", receipt);

            Ok(())
        }
        WalletCommands::SweepAll {
            token,
            rpc
        } => {
            let funding_wallet = store.get("wallet".to_owned()).unwrap();
            let chain = chain::ChainConfigWithMeta::new(rpc).await?;
            let client = chain.client();

            // Load the safe
            let safe_file = config_dir.join("safe");
            let safe_address = hex::decode(std::fs::read_to_string(safe_file)?)?;
            let safe = Safe::load(H160::from_slice(&safe_address), client.clone()).await;

            // Connect to the BZZ token contract
            let contract =
                PermittableToken::new(token.unwrap_or(chain.get_address("BZZ_ADDRESS_GNOSIS").unwrap()), client.clone());

            // Get all the bee node wallets from the store
            // iterate over them and call transfer on the BZZ token for each one
            let wallets = store.get_all();

            // filter out the funding wallet
            let wallets = wallets
                .into_iter()
                .filter(|(name, _)| name != "wallet")
                .collect::<Vec<(String, Wallet<SigningKey>)>>();

            let mut multicall = Multicall::<Provider<Http>>::new(client.clone(), None).await?;

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
                    chain,
                    client,
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
pub struct CliTransactionHandler<M, S, T>
where
    M: Middleware,
    S: Signer,
{
    wallet: Wallet<SigningKey>,
    call: ContractCall<SignerMiddleware<M, S>, T>,
    description: String,
}

impl<M, S, T> CliTransactionHandler<M, S, T>
where
    M: Middleware,
    S: Signer,
    T: Detokenize,
{
    /// Create a new transaction handler
    pub fn new(
        wallet: Wallet<SigningKey>,
        call: ContractCall<SignerMiddleware<M, S>, T>,
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
        chain: &chain::ChainConfigWithMeta,
        num_confirmations: usize,
    ) -> Result<TransactionReceipt> {
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

#[derive(Eip712, EthAbiType, Clone)]
#[eip712()]
struct Permit {
    holder: Address,
    spender: Address,
    nonce: U256,
    expiry: U256,
    allowed: bool,
}

async fn legacy_permit_approve<M>(
    wallet: Wallet<SigningKey>,
    token: H160,
    spender: H160,
    nonce_offset: Option<U256>,
    client: Arc<M>,
) -> Result<Bytes>
where
    M: Middleware,
{
    abigen!(
        LegacyPermit,
        r#"[
            function name() external view returns (string)
            function nonces(address owner) external view returns (uint256)
            function permit(address _holder, address _spender, uint256 _nonce, uint256 _expiry, bool _allowed, uint8 _v, bytes32 _r, bytes32 _s) external
        ]"#,
    );

    let contract = LegacyPermit::new(token, client.clone());

    let name: String = contract
        .name()
        .call()
        .await
        .map_err(|e| anyhow!("Failed to get name: {}", e))?;

    let nonce: U256 = contract
        .nonces(wallet.address())
        .call()
        .await
        .map_err(|e| anyhow!("Failed to get nonce: {}", e))?;

    let expiry = U256::MAX;

    let chain_id = client.clone().get_chainid().await.unwrap();

    let domain = EIP712Domain {
        name: Some(name),
        version: Some("1".into()),
        chain_id: Some(chain_id),
        verifying_contract: Some(token),
        salt: None,
    };

    let permit = Permit {
        holder: wallet.address(),
        spender,
        nonce: nonce + nonce_offset.unwrap_or_default(),
        expiry,
        allowed: true,
    };

    let legacy_permit_message = EIP712WithDomain::new(permit)?.set_domain(domain);

    let signature: Signature = wallet.sign_typed_data(&legacy_permit_message).await?;

    // Return the permit call data
    Ok(contract
        .permit(
            wallet.address(),
            spender,
            nonce + nonce_offset.unwrap_or_default(),
            expiry,
            true,
            signature.v.try_into().unwrap(),
            signature.r.into(),
            signature.s.into(),
        )
        .calldata()
        .unwrap())
}

/// Get the default configuration directory and the wallet store
fn get_cwd_config() -> (PathBuf, WalletStore) {
    let path = PathBuf::from(".");
    let store_dir = path.join(DEFAULT_CONFIG_DIR);

    let store = WalletStore::load(store_dir.clone()).unwrap();

    (store_dir, store)
}
