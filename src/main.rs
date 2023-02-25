use std::{collections::HashMap, sync::Arc};
use clap::Parser;
use eyre::Result;

use ethers::prelude::*;
use passwords::PasswordGenerator;

use bee_overlay_miner::{Opts, Commands, contracts::stake_registry::{StakeRegistry, StakeRegistryEvents}};

const STAKEREGISTRY_START_BLOCK: u64 = 25527075;

// const BZZ_CONTRACT_ADDRESS: &str = "0xdBF3Ea6F5beE45c02255B2c26a16F300502F68da";

#[tokio::main]
async fn main() -> Result<()> {
    // Parse the command line arguments
    let opts: Opts = Opts::parse();

    // match the subcommand
    match opts.subcommand {
        // if the subcommand is to mine an overlay address
        Commands::MineOverlayAddress(opts) => {
            let kad = Kademlia::new(opts.depth);

            println!("Mining overlay address for neighbourhood {}/{}", opts.target, kad.num_neighbourhoods());

            // get the base overlay address for the target neighbourhood and depth
            let base_overlay_address = kad.get_base_overlay_address(opts.target);

            // calculate the bit-mask for the depth
            let bit_mask = kad.neighbourhood_bitmask();

            let mut count = 0;

            let pg = PasswordGenerator {
                length: 32,
                numbers: true,
                lowercase_letters: true,
                uppercase_letters: true,
                symbols: false,
                spaces: false,
                exclude_similar_characters: true,
                strict: true,
            };

            let password = pg.generate_one().unwrap();

            // create a temporary directory to store the keystore
            let dir = tempfile::tempdir()?;
            let path = dir.path();

            println!("Password: {}", password);

            loop {
                // increment the count
                count += 1;

                // create a new keystore with the password
                let (wallet, uuid) = LocalWallet::new_keystore(path, &mut rand::thread_rng(), password.clone(), None)?;

                // calculate the overlay address for the keypair
                let overlay_address = wallet.address().overlay_address(opts.network_id, opts.nonce);

                // use the bit mask to compare the overlay address to the base overlay address
                let mut match_found = true;
                for i in 0..32 {
                    if overlay_address[i] & bit_mask[i] != base_overlay_address[i] & bit_mask[i] {
                        match_found = false;
                        break;
                    }
                }

                // if a match was found, print the keypair and exit
                if match_found {
                    // get the private key from the wallet
                    let private_key = wallet.signer().to_bytes();

                    // if a match was found, print the keypair and exit
                    println!("Match found after {} iterations...", count);

                    // print the base overlay address in hex
                    println!("Base overlay address: 0x{}", hex::encode(base_overlay_address));
                    // print the overlay address in hex
                    println!("Overlay address: 0x{}", hex::encode(overlay_address));
                    // print the private key in hex
                    println!("Private key: 0x{}", hex::encode(private_key));
                    // print the wallet password
                    println!("Password: {}", password);

                    // get the current directory
                    let current_dir = std::env::current_dir()?;

                    // get the path to the keystore
                    let keystore_path = path.join(uuid.to_string());

                    // copy the keystore to the current directory and give it the name `overlay_address.json`
                    std::fs::copy(keystore_path, current_dir.join(format!("{}.json", hex::encode(overlay_address))))?;

                    // write the password to a file
                    std::fs::write(current_dir.join(format!("{}.password", hex::encode(overlay_address))), password)?;

                    break;
                }

            }

            // if a match was not found, delete the keystore
            dir.close()?;

        }
        // if the subcommand is to dump the overlay addresses
        Commands::DumpOverlayAddresses(opts) => {
            println!("Dumping base overlay addresses for depth {}", opts.depth);
            
            let kad = Kademlia::new(opts.depth);

            // dump the overlay addresses
            let base_overlay_addresses = kad.get_base_overlay_addresses();

            // print all the first overlay addresses
            for address in base_overlay_addresses {
                // output the first overlay address in hex
                println!("0x{}", hex::encode(address));
            }
        }
        // if the subcommand is to calculate the overlay address
        Commands::CalcOverlayAddress(opts) => {
            println!("Calculating overlay for address: 0x{}", hex::encode(opts.address));

            // calculate the overlay address
            let overlay_address = opts.address.overlay_address(opts.network_id, opts.nonce);
            // output the overlay address in hex
            println!("The overlay address is: 0x{}", hex::encode(overlay_address));
        }
        // dump a funding tear sheet, which is a csv file with the ethereum address, and the amount of BZZ and xDAI to fund the address with
        Commands::FundingTearSheet => {
            // Iterate over all keystores in the current directory
            // and print the ethereum address, and target balance of 10 BZZ

            // get the current directory
            let current_dir = std::env::current_dir()?;
            // get the list of files in the current directory
            let files = std::fs::read_dir(current_dir)?;

            println!("overlay,address,xbzz_amount,xdai_amount");

            // iterate over the files
            for file in files {
                // get the file path
                let file_path = file?.path();

                match file_path.extension() {
                    Some(ext) => {
                        // if the file is a json file
                        if ext == "json" {
                            // the password is in a file with the same name as the keystore, but with the extension `.password.txt`
                            let password_file_path = file_path.with_extension("password.txt");

                            // read the password file
                            let password = std::fs::read_to_string(password_file_path)?;

                            let wallet = LocalWallet::decrypt_keystore(file_path.clone(), password)?;

                            // get the ethereum address
                            let address = wallet.address() as H160;

                            // calculate the overlay address
                            let overlay_address = hex::encode(address.overlay_address(1, None));

                            // print address as hex
                            let f = |x: &H160| format!("{:#x}", x);

                            println!("{},{},{},{}", overlay_address, f(&address), "100000000000000000", "100000000000000000");
                        }
                    }
                    None => {}
                }
            }
        }
        // if the subcommand is to dump all the stakes
        Commands::DumpAllStakes(opts) => {
            println!("Dumping all stakes...");

            let kad = Kademlia::new(opts.depth);

            // dump all the stakes
            let stakes = get_all_stakes(opts.address, opts.rpc, &kad).await.unwrap();

            // number of neighbourhoods
            let num_neighbourhoods = kad.num_neighbourhoods();

            // print all the stakes iterating over by specific index
            for i in 0..stakes.len() {
                // get the overlay address
                let overlay_address = &stakes[i].0;
                // get the stake
                let stake = stakes[i].1;
                // get the neighbourhood
                let neighbourhood = stakes[i].2;

                println!("0x{},{},{}", hex::encode(overlay_address), stake, neighbourhood);
            }

            // Do statistical analysis per neighbourhood. Calculate:
            // - Total number of overlay addresses
            // - Stake per neighbourhood
            // - Average stake per neighbourhood

            // create a vector to hold the total stakes per neighbourhood
            let mut total_stakes: Vec<U256> = vec![U256::zero(); num_neighbourhoods as usize];
            // create a vector to hold the number of overlay addresses per neighbourhood
            let mut num_overlay_addresses: Vec<u32> = vec![0; num_neighbourhoods as usize];

            // iterate over all the stakes by specific index
            for i in 0..stakes.len() {
                // get the neighbourhood
                let neighbourhood = stakes[i].2;
                // get the stake
                let stake = stakes[i].1;

                // add the stake to the total stakes for the neighbourhood
                total_stakes[neighbourhood as usize] += stake;
                // increment the number of overlay addresses for the neighbourhood
                num_overlay_addresses[neighbourhood as usize] += 1;
            }

            // print the total stakes per neighbourhood
            println!("Total stakes per neighbourhood:");
            for i in 0..num_neighbourhoods {
                println!("neighbourhood {}/{}: {}", i, num_neighbourhoods, total_stakes[i as usize]);
            }

            // print the average stakes per neighbourhood
            println!("Average stakes per neighbourhood:");
            for i in 0..num_neighbourhoods {
                // guard against divide by zero
                if num_overlay_addresses[i as usize] == 0 {
                    println!("neighbourhood {}/{}: 0", i, num_neighbourhoods);
                    continue;
                }
                println!("neighbourhood {}/{}: {}", i, num_neighbourhoods, total_stakes[i as usize] / U256::from(num_overlay_addresses[i as usize]));
            }

            // print the total number of overlay addresses per neighbourhood
            println!("Total number of overlay addresses per neighbourhood:");
            for i in 0..num_neighbourhoods {
                println!("neighbourhood {}/{}: {}", i, num_neighbourhoods, num_overlay_addresses[i as usize]);
            }

            // print the total number of overlay addresses
            println!("Total number of overlay addresses: {}", stakes.len());

            // print the total stake
            let mut total_stake = U256::zero();
            for stake in total_stakes {
                total_stake += stake;
            }
            println!("Total stake: {}", total_stake);

            // print the average stake
            println!("Average stake: {}", total_stake / U256::from(stakes.len()));

            println!("Done!");
        }
    }

    return Ok(());
}

/// Get all the stakes from the contract. Returns a vector of tuples containing:
/// 1. the overlay address
/// 2. the stake
/// 3. the neighbourhood
/// The vector is sorted by overlay address
async fn get_all_stakes(address: H160, rpc: String, kad: &Kademlia) -> Result<Vec<([u8; 32], U256, u32)>> {
    let provider = Provider::<Http>::try_from(rpc).unwrap();
    let client = Arc::new(provider);

    // StakeRegistry contract
    let contract = StakeRegistry::new(address, Arc::clone(&client));

    // Create a hashmap to hold the overlay addresses and stakes
    let mut stakes: HashMap<[u8; 32], U256> = HashMap::new();

    // Subscribe to the StakeUpdated event
    let events = contract.events().from_block(STAKEREGISTRY_START_BLOCK);
    let logs = events.query().await?;

    // iterate over the events
    for log in logs.iter() {
        match log {
            // if the event is a StakeUpdated event
            StakeRegistryEvents::StakeUpdatedFilter(f) => {
                // get the overlay address
                let overlay = f.overlay;
                // get the stake
                let stake = f.stake_amount;

                // add the overlay address and stake to the hashmap if the stake is greater than 0
                // if the overlay address already exists, add the new stake to the existing stake
                if !stake.is_zero() {
                    stakes.entry(overlay).and_modify(|e| *e += stake).or_insert(stake);
                }
            }
            _ => {}
        }
    }

    // create a vector to hold the overlay addresses and stakes
    let mut stakes_vec: Vec<([u8; 32], U256, u32)> = Vec::new();

    // iterate over the hashmap and add the overlay addresses and stakes to the vector
    for (overlay_address, stake) in stakes {
        stakes_vec.push((overlay_address, stake, kad.get_neighbourhood(overlay_address)));
    }

    // sort the vector by overlay address
    stakes_vec.sort_by(|a, b| a.0.cmp(&b.0));

    return Ok(stakes_vec);
}

pub struct Kademlia {
    pub depth: u32,
}

impl Kademlia {
    /// Create a new Kademlia instance
    /// The depth is the number of bits to use for the neighbourhood
    /// The depth must be between 0 and 31 (inclusive)
    pub fn new(depth: u32) -> Self {
        // guard against invalid depth
        if depth > 31 {
            panic!("Depth must be between 0 and 31 (inclusive)");
        }
        Self { depth }
    }

    /// Calculate the number of neighbourhoods for a given depth
    /// The number of neighbourhoods is 2^depth
    pub fn num_neighbourhoods(&self) -> u32 {
        2u32.pow(self.depth)
    }

    /// Calculate a bit-mask for a given depth
    /// The bit-mask is a 256 bit value, with the first `depth` bits being 1, and the rest being 0
    pub fn neighbourhood_bitmask(&self) -> [u8; 32] {
        // create a bytes array to hold the bit-mask
        let mut bit_mask = [0u8; 32];

        // set the first `depth` bits to 1
        for i in 0..self.depth {
            bit_mask[i as usize / 8] |= 1 << (i % 8);
        }

        // return the bit-mask
        bit_mask
    }

    /// Calculate the neighbourhood for a given overlay address
    pub fn get_neighbourhood(&self, overlay_address: [u8; 32]) -> u32 {
        // Get the first 4 bytes of the overlay address a u32 big endian
        let mut neighbourhood = [0u8; 4];
        neighbourhood.copy_from_slice(&overlay_address[0..4]);

        let neighbourhood = u32::from_be_bytes(neighbourhood) / self.neighbourhood_size();

        neighbourhood
    }

    /// Calculate the size of a neighbourhood for a given depth
    pub fn neighbourhood_size(&self) -> u32 {
        (2u64.pow(32) / 2u64.pow(self.depth)).try_into().unwrap()
    }

    /// For a given depth and neighbourhood, calculate the base overlay address
    pub fn get_base_overlay_address(&self, neighbourhood: u32) -> [u8; 32] {
        // create a bytes array to hold the base overlay address
        let mut address = [0u8; 32];

        // calculate the neighbourhood offset
        let offset: u32 = neighbourhood * self.neighbourhood_size();

        // convert the neighbourhood offset to bytes
        let offset_bytes = offset.to_be_bytes();

        // copy the neighbourhood offset bytes into the base overlay address
        address[0..4].copy_from_slice(&offset_bytes);

        // return the base overlay address
        address
    }

    /// For a given depth, calculate the base overlay address for each neighbourhood
    pub fn get_base_overlay_addresses(&self) -> Vec<[u8; 32]> {
        // create a vector to hold the base overlay addresses
        let mut addresses = Vec::new();

        // iterate over all possible neighbourhoods
        for neighbourhood in 0..self.num_neighbourhoods() {
            // add the base overlay address to the vector
            addresses.push(self.get_base_overlay_address(neighbourhood));
        }

        // return the vector of base overlay addresses
        addresses
    }
}

trait OverlayCalc {
    fn overlay_address(&self, network_id: u64, nonce: Option<[u8; 32]>) -> [u8; 32];
}

impl OverlayCalc for H160 {
    fn overlay_address(&self, network_id: u64, nonce: Option<[u8; 32]>) -> [u8; 32] {
        // get the public key of the signer
        // this will be 256 bits for the public key, 64 bits for the network id, and 256 bits for the nonce
        let mut data = [0u8; 20 + 8 + 32];
        // copy the public key into the first 32 bytes
        data[0..20].copy_from_slice(self.as_bytes());
        // copy the network id into the next 8 bytes
        data[20..28].copy_from_slice(&network_id.to_le_bytes());
        // copy the nonce into the last 32 bytes
        let nonce = nonce.unwrap_or([0u8; 32]);
        data[28..60].copy_from_slice(&nonce);
    
        // return the hash
        ethers::utils::keccak256(data)
    }
}
