use std::{path::{Path, PathBuf}, collections::HashMap};

use eyre::{anyhow, Result};
use ethers::{prelude::k256::ecdsa::SigningKey, prelude::*, types::H160};
use passwords::PasswordGenerator;

use crate::{WalletArgs, WalletCommands, safe::Safe, chain};

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
            let result = store.create_wallet(
                &bees_dir,
                None,
                |_key| "wallet".to_string(), 
                |_key| true
            );

            // If the wallet was created successfully, print the address
            if let Ok((wallet, password)) = result {
                println!("Wallet created: 0x{}", hex::encode(wallet.address()));
                println!("Password: {}", password);
            }

            Ok(())
        },
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

            let chain = chain::Chain::new(rpc).await?;

            // Create the Safe
            let safe = Safe::new(
                vec![wallet.address()],
                1.into(),
                None,
                &chain,
                wallet
            ).await;

            println!("Safe created: 0x{}", hex::encode(safe.address));

            // Save the safe's address to a file in the bees directory
            let safe_file = bees_dir.join("safe");
            std::fs::write(safe_file, hex::encode(safe.address))?;

            Ok(())
        },
        WalletCommands::CalculateFundingRequirements { max_bzz, xdai, rpc } => {
            todo!()
        },
        WalletCommands::SwapAndBridge { mainnet_rpc, gnosis_rpc, max_bzz, xdai } => {
            todo!()
        },
        WalletCommands::DistributeFunds { max_bzz, xdai, rpc } => {
            todo!()
        },
        WalletCommands::PermitApproveAll { rpc } => {
            todo!()
        },
        WalletCommands::SweepAll { rpc } => {
            todo!()
        },
        WalletCommands::StakeAll { rpc } => {
            todo!()
        },
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
        where F: FnOnce(Wallet<SigningKey>) -> bool, 
            N: FnOnce(Wallet<SigningKey>) -> String
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
        println!("{} -> {}", keystore_path.display(), new_keystore_path.display());
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
