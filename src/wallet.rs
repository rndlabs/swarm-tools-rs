use std::{
    collections::HashMap,
    path::{Path, PathBuf}, io::Write,
};

use ethers::{prelude::k256::ecdsa::SigningKey, prelude::{*, builders::ContractCall}, types::H160, abi::Detokenize};
use eyre::{anyhow, Result};
use passwords::PasswordGenerator;

use crate::{chain, safe::Safe, WalletArgs, WalletCommands};

pub async fn process(args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommands::Generate => {
            // Get the path to the wallet directory
            let path = PathBuf::from(".");
            let bees_dir = path.join("bees");

            let mut store = WalletStore::load(bees_dir.clone()).unwrap();
            if store.get("wallet".to_owned()).is_ok() {
                return Err(anyhow!("Wallet already exists"));
            }

            // Wallet doesn't exist, so create a new one
            let result =
                store.create_wallet(&bees_dir, None, |_key| "wallet".to_string(), |_key| true);

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!("Wallet created: 0x{}", hex::encode(wallet.address()));
                println!("Password: {}", password);
            }

            Ok(())
        }
        WalletCommands::InitSafe { rpc } => {
            // Get the path to the wallet directory
            let path = PathBuf::from(".");
            let bees_dir = path.join("bees");

            let store = WalletStore::load(bees_dir.clone()).unwrap();
            let wallet = store.get("wallet".to_owned()).unwrap();

            // Determine if the Safe has already been created
            let safe_file = bees_dir.join("safe");
            if safe_file.exists() {
                return Err(anyhow!("Safe already exists"));
            }

            let chain = chain::ChainConfigWithMeta::new(rpc).await?;
            let client = chain.client();

            // Create the Safe
            let safe = Safe::new(vec![wallet.address()], 1.into(), None, chain, client, wallet).await;

            println!("Safe created: 0x{}", hex::encode(safe.address));

            // Save the safe's address to a file in the bees directory
            let safe_file = bees_dir.join("safe");
            std::fs::write(safe_file, hex::encode(safe.address))?;

            Ok(())
        }
        WalletCommands::CalculateFundingRequirements { max_bzz, xdai, rpc } => {
            todo!()
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
        WalletCommands::PermitApproveAll { rpc } => {
            todo!()
        }
        WalletCommands::SweepAll { rpc } => {
            todo!()
        }
        WalletCommands::StakeAll { rpc } => {
            todo!()
        }
    }
}

pub struct TransactionHandler<M, S, T> 
where
    M: Middleware,
    S: Signer,
{
    wallet: Wallet<SigningKey>,
    call: ContractCall<SignerMiddleware<M, S>, T>,
    description: String,
}

impl<M, S, T> TransactionHandler<M, S, T>
where
    M: Middleware,
    S: Signer,
    T: Detokenize,
{
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

    pub async fn handle(&self, chain: &chain::ChainConfigWithMeta, num_confirmations: usize) -> Result<TransactionReceipt> {
        let client = chain.client();

        // Get the gas estimate and gas price
        let gas_limit = client.estimate_gas(&self.call.tx, None).await?;
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
        println!("  From: 0x{}", hex::encode(self.wallet.address()));
        println!("  To: 0x{}", hex::encode(self.call.tx.to().unwrap().as_address().unwrap()));
        println!("  Data: 0x{}", hex::encode(self.call.tx.data().unwrap()));
        println!("  Gas Limit: {}", gas_limit);
        println!("  Gas Price: {}", ethers::utils::format_units(gas_price, "gwei").unwrap());
        println!("  Gas Cost: {}", ethers::utils::format_units(gas_cost, "ether").unwrap());
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
        println!("Waiting for the transaction to be mined...");
        let receipt = tx.confirmations(num_confirmations).await.unwrap().unwrap();

        Ok(receipt)
    }
}

pub struct WalletStore {
    path: PathBuf,
    wallets: HashMap<String, Wallet<SigningKey>>,
    pg: PasswordGenerator,
}

impl WalletStore {
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

    pub fn insert_wallet(&mut self, name: String, wallet: Wallet<SigningKey>) -> Result<()> {
        if self.wallets.contains_key(&name) {
            return Err(anyhow!("Wallet already exists"));
        }

        self.wallets.insert(name, wallet);
        Ok(())
    }

    pub fn get(&self, name: String) -> Result<Wallet<SigningKey>> {
        match self.wallets.get(&name) {
            Some(wallet) => Ok(wallet.clone()),
            None => Err(anyhow!("Wallet not found")),
        }
    }

    pub fn get_address(&self, name: String) -> Result<H160> {
        self.get(name).map(|wallet| wallet.address())
    }

    pub fn get_name(&self, address: H160) -> Result<String> {
        for (name, wallet) in self.wallets.iter() {
            if wallet.address() == address {
                return Ok(name.clone());
            }
        }

        Err(anyhow!("Wallet not found"))
    }

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
