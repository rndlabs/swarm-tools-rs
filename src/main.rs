use clap::{Args, Parser, Subcommand};
use ethers::types::H160;
use eyre::{anyhow, Result};

use ethers::prelude::*;
use passwords::PasswordGenerator;

use swarm_tools::{
    game::Game, overlay::Overlay, parse_bytes32, parse_name_or_address, postage::PostOffice,
    redistribution::get_avg_depth, topology::Topology,
};

const POSTAGESTAMP_START_BLOCK: &str = "25527076";

/// Swarm tools CLI
#[derive(Debug, Parser)]
#[clap(name = "swarm-tools", version, author, about)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Calculators / tools for neighbourhoods
    Topology(TopologyArgs),
    /// Calculators / miner for overlays
    Overlay(OverlayArgs),
    /// Analyse neighbourhood distribution for the schelling game
    #[command(arg_required_else_help = true)]
    Redistribution {
        /// The address of the stake registry contract
        #[arg(long, value_parser = parse_name_or_address)]
        stake_registry: Option<H160>,
        /// Storage radius for analysis
        #[arg(short, default_value = "8")]
        radius: u32,
        /// RPC to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
    /// Analyse postage stamps
    #[command(arg_required_else_help = true)]
    PostageStamp {
        /// The address of the postage stamp contract
        #[arg(long, value_parser = parse_name_or_address)]
        postage_stamp_contract_address: Option<H160>,
        /// The block to start analysis from
        #[arg(long, default_value = POSTAGESTAMP_START_BLOCK)]
        start_block: u64,
        /// RPC to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct TopologyArgs {
    #[command(subcommand)]
    command: TopologyCommands,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct OverlayArgs {
    #[command(subcommand)]
    command: OverlayCommands,
}

#[derive(Debug, Subcommand)]
enum TopologyCommands {
    /// Given a radius, output the base overlay address for all neighbourhoods
    DumpBaseOverlays(RadiusArgs),
    /// Given a radius, output the number of neighbourhoods
    NumNeighbourhoods(RadiusArgs),
    /// Calculate the daily average reported storage radius
    ActualAvgStorageRadius {
        /// The address of the stake registry contract
        #[arg(long, value_parser = parse_name_or_address)]
        redistribution_address: Option<H160>,
        /// RPC to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[derive(Debug, Subcommand)]
enum OverlayCommands {
    /// Calculate an overlay address from it's components
    Calculate {
        #[arg(
            short,
            help = "The ethereum address for the overlay",
            value_parser = parse_name_or_address
        )]
        address: H160,
        #[arg(short, help = "The Swarm network ID")]
        network_id: u32,
        #[arg(
            long,
            help = "A nonce (for grand-fathered nodes, no longer used)",
            value_parser = parse_bytes32
        )]
        nonce: Option<[u8; 32]>,
    },
    /// Determine which neighbourhood an overlay is in
    Neighbourhood {
        #[arg(
            short,
            help = "The radius to calculate the neighbourhood population with"
        )]
        radius: u32,
        #[arg(
            help = "The overlay from which to determine the neighbourhood with",
            value_parser = parse_bytes32
        )]
        overlay: [u8; 32],
    },
    /// Mine an overlay address into a specific neighbourhood
    Mine {
        #[arg(short, help = "The radius to calculate the neighbourhoods with")]
        radius: u32,
        #[arg(short, help = "The neighbourhood to mine the address into")]
        neighbourhood: u32,
        #[arg(long, help = "The Swarm network ID")]
        network_id: u32,
        #[arg(
            long,
            help = "The nonce, if any to use for mining",
            value_parser = parse_bytes32
        )]
        nonce: Option<[u8; 32]>,
    },
}

#[derive(Debug, Args)]
struct RadiusArgs {
    #[arg(short, help = "The radius used for determining neighbourhood topology")]
    radius: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match args.command {
        Commands::Topology(topology) => match topology.command {
            TopologyCommands::DumpBaseOverlays(radius) => {
                let store = Topology::new(radius.radius);

                println!("Base overlay addresses for radius {}:", radius.radius);
                for i in 0..store.num_neighbourhoods() {
                    println!("{}", hex::encode(store.get_base_overlay_address(i)));
                }
            }
            TopologyCommands::NumNeighbourhoods(radius) => {
                let store = Topology::new(radius.radius);

                println!(
                    "Number of neighbourhoods for radius {}: {}",
                    radius.radius,
                    store.num_neighbourhoods()
                );
            }
            TopologyCommands::ActualAvgStorageRadius {
                redistribution_address,
                rpc,
            } => {
                let chain = swarm_tools::chain::Chain::new(rpc).await?;

                let (avg_depth, sample_size) = get_avg_depth(
                    redistribution_address.unwrap_or(chain.get_address("REDISTRIBUTION").unwrap()),
                    chain.client(),
                )
                .await?;

                println!(
                    "Average storage radius: {} (from {} samples)",
                    avg_depth, sample_size
                );
            }
        },
        Commands::Overlay(overlay) => {
            match overlay.command {
                OverlayCommands::Calculate {
                    address,
                    network_id,
                    nonce,
                } => {
                    println!(
                        "Overlay address: 0x{}",
                        hex::encode(address.overlay_address(network_id, nonce))
                    );
                }
                OverlayCommands::Neighbourhood { radius, overlay } => {
                    let store = Topology::new(radius);

                    println!(
                        "Neighbourhood for overlay {} with radius {} is {}",
                        hex::encode(overlay),
                        radius,
                        store.get_neighbourhood(overlay)
                    );
                }
                OverlayCommands::Mine {
                    radius,
                    neighbourhood,
                    network_id,
                    nonce,
                } => {
                    let store = Topology::new(radius);

                    // guard against invalid neighbourhoods
                    if neighbourhood >= store.num_neighbourhoods() {
                        return Err(anyhow!(
                            "Invalid neighbourhood {} for radius {}. Max neighbourhood is {}",
                            neighbourhood,
                            radius,
                            store.num_neighbourhoods() - 1
                        ));
                    }

                    println!(
                        "Mining overlay address for neighbourhood {}/{}",
                        neighbourhood,
                        store.num_neighbourhoods() - 1
                    );

                    // get the base overlay address for the target neighbourhood and depth
                    let base_overlay_address = store.get_base_overlay_address(neighbourhood);

                    // calculate the bit-mask for the depth
                    let bit_mask = store.neighbourhood_bitmask();

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

                    let mut count = 0;

                    loop {
                        // increment the count
                        count += 1;

                        // create a new keystore with the password
                        let (wallet, uuid) = LocalWallet::new_keystore(
                            path,
                            &mut rand::thread_rng(),
                            password.clone(),
                            None,
                        )?;

                        // calculate the overlay address for the keypair
                        let overlay_address = wallet.address().overlay_address(network_id, nonce);

                        // use the bit mask to compare the overlay address to the base overlay address
                        let mut match_found = true;
                        for i in 0..32 {
                            if overlay_address[i] & bit_mask[i]
                                != base_overlay_address[i] & bit_mask[i]
                            {
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
                            println!(
                                "Base overlay address: 0x{}",
                                hex::encode(base_overlay_address)
                            );
                            // print the overlay address in hex
                            println!("Overlay address: 0x{}", hex::encode(overlay_address));
                            // print the address in hex
                            println!("Address: 0x{}", hex::encode(wallet.address().as_bytes()));
                            // print the private key in hex
                            println!("Private key: 0x{}", hex::encode(private_key));
                            // print the wallet password
                            println!("Password: {}", password);

                            // get the current directory
                            let current_dir = std::env::current_dir()?;

                            // get the path to the keystore
                            let keystore_path = path.join(uuid);

                            // copy the keystore to the current directory and give it the name `overlay_address.json`
                            std::fs::copy(
                                keystore_path,
                                current_dir.join(format!("{}.json", hex::encode(overlay_address))),
                            )?;

                            // write the password to a file
                            std::fs::write(
                                current_dir
                                    .join(format!("{}.password", hex::encode(overlay_address))),
                                password,
                            )?;

                            break;
                        }
                    }

                    // if a match was not found, delete the keystore
                    dir.close()?;
                }
            }
        }
        Commands::Redistribution {
            stake_registry,
            radius,
            rpc,
        } => {
            let chain = swarm_tools::chain::Chain::new(rpc).await?;
            let store = Topology::new(radius);

            let game = Game::new(
                stake_registry.unwrap_or(chain.get_address("REDISTRIBUTION").unwrap()),
                chain.client(),
                &store,
            )
            .await?;

            game.stats();
        }
        Commands::PostageStamp {
            postage_stamp_contract_address,
            start_block,
            rpc,
        } => {
            let chain = swarm_tools::chain::Chain::new(rpc).await?;

            let post_office = PostOffice::new(
                postage_stamp_contract_address
                    .unwrap_or(chain.get_address("POSTAGE_STAMP").unwrap()),
                chain.client(),
                start_block,
            )
            .await?;

            println!("{}", post_office);

            let num_chunks = post_office.num_chunks();
            let total_size_gb = num_chunks * 4096 / 1024 / 1024 / 1024;
            let round_reward = post_office.round_reward(152);

            println!("Total chunks: {}", num_chunks);
            println!("Total size: {} GB", total_size_gb);
            println!(
                "Round reward: {} BZZ",
                ethers::utils::format_units(round_reward, 16)?
            );
        }
    }

    Ok(())
}
