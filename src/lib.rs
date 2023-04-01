use clap::{Args, Parser, Subcommand};
use ethers::prelude::*;
use eyre::Result;
use std::str::FromStr;
use std::sync::Arc;

use crate::postage::POSTAGESTAMP_START_BLOCK;
use crate::{
    game::Game,
    overlay::{MinedAddress, OverlayCalculator},
    postage::PostOffice,
    redistribution::get_avg_depth,
    topology::Topology,
};

pub mod chain;
pub mod contracts;
pub mod erc20;
pub mod exchange;
pub mod game;
pub mod overlay;
pub mod postage;
pub mod redistribution;
pub mod safe;
pub mod topology;
pub mod wallet;

pub type OverlayAddress = [u8; 32];

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Calculators / tools for neighbourhoods
    Topology(TopologyArgs),
    /// Calculators / miner for overlays
    Overlay(OverlayArgs),
    /// Analyse neighbourhood distribution for the schelling game
    #[command(arg_required_else_help = true)]
    Game {
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
    /// Node funding related tools
    Wallet(WalletArgs),
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TopologyArgs {
    #[command(subcommand)]
    command: TopologyCommands,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct OverlayArgs {
    #[command(subcommand)]
    command: OverlayCommands,
}

#[derive(Debug, Subcommand)]
pub enum TopologyCommands {
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
pub enum OverlayCommands {
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
        overlay: OverlayAddress,
    },
    /// Automatically mine overlay addresses into the optimal neighbourhoods
    /// for a given radius
    AutoMine {
        #[arg(short, help = "The number of addresses to mine")]
        num_addresses: u32,
        #[arg(long, help = "The Swarm network ID")]
        network_id: u32,
        /// RPC to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
    /// Mine an overlay address into a specific neighbourhood
    ManualMine {
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
pub struct RadiusArgs {
    #[arg(short, help = "The radius used for determining neighbourhood topology")]
    radius: u32,
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommands {
    /// Generate a new funding wallet
    Generate,
    /// Initialize a Safe wallet on Gnosis Chain
    InitSafe {
        /// RPC to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
    /// Swap and bridge the required amount of DAI to BZZ and then bridge the BZZ to xDAI
    SwapAndBridge {
        #[arg(
            long,
            default_value = "http://mainnet:8545",
            help = "Ethereum Mainnet RPC to connect to"
        )]
        mainnet_rpc: String,
        #[arg(
            long,
            default_value = "http://localhost:8545",
            help = "Gnosis Chain RPC to connect to"
        )]
        gnosis_rpc: String,
        #[arg(short, help = "Set a maximum amount of BZZ to fund each node with")]
        max_bzz: Option<U256>,
        #[arg(short, help = "Set the amount of xDAI to fund each node with")]
        xdai: Option<U256>,
    },
    /// Fund all the bee nodes with funds in a Safe wallet.
    DistributeFunds {
        #[arg(short, help = "Set a maximum amount of BZZ to fund each node with")]
        max_bzz: Option<U256>,
        #[arg(short, help = "Set the amount of xDAI to fund each node with")]
        xdai: Option<U256>,
        #[arg(
            long,
            default_value = "http://localhost:8545",
            help = "RPC to connect to"
        )]
        rpc: String,
    },
    /// Set token approvals on all wallets (Safe wallet and StakeRegistry).
    PermitApproveAll {
        #[arg(
            long,
            value_parser = parse_name_or_address,
            help = "The address of the token to mass approve."
        )]
        token: Option<H160>,
        #[arg(
            long,
            default_value = "http://localhost:8545",
            help = "RPC to connect to"
        )]
        rpc: String,
    },
    /// Sweep all the BZZ from the node wallets into the Safe wallet.
    SweepAll {
        #[arg(
            long,
            value_parser = parse_name_or_address,
            help = "The address of the token to mass approve."
        )]
        token: Option<H160>,
        #[arg(
            long,
            default_value = "http://localhost:8545",
            help = "RPC to connect to"
        )]
        rpc: String,
    },
    /// Stake all the BZZ in the nodes' wallets
    StakeAll {
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

/// A `clap` `value_parser` that parses a `NameOrAddress` from a string
pub fn parse_name_or_address(s: &str) -> Result<H160> {
    Ok(H160::from_str(s)?)
}

/// A `clap` `value_parser` that removes a `0x` prefix if it exists
pub fn strip_0x_prefix(s: &str) -> Result<String, &'static str> {
    Ok(s.strip_prefix("0x").unwrap_or(s).to_string())
}

/// A `clap` `value_parser` that parses a string into a 32 byte array
pub fn parse_bytes32(s: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    let s = strip_0x_prefix(s)?;
    hex::decode_to_slice(s, &mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Swarm tools CLI
#[derive(Debug, Parser)]
#[clap(name = "swarm-tools", version, author, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

pub async fn run(args: Cli) -> Result<()> {
    match args.command {
        Commands::Topology(topology) => match topology.command {
            TopologyCommands::DumpBaseOverlays(radius) => {
                let t = Topology::new(radius.radius);

                println!("Base overlay addresses for radius {}:", radius.radius);
                for i in 0..t.num_neighbourhoods() {
                    println!("{}", hex::encode(t.get_base_overlay_address(i)));
                }
            }
            TopologyCommands::NumNeighbourhoods(radius) => {
                let t = Topology::new(radius.radius);

                println!(
                    "Number of neighbourhoods for radius {}: {}",
                    radius.radius,
                    t.num_neighbourhoods()
                );
            }
            TopologyCommands::ActualAvgStorageRadius {
                redistribution_address,
                rpc,
            } => {
                let client = Arc::new(Provider::<Http>::try_from(rpc)?);
                let chain = crate::chain::ChainConfigWithMeta::new(client).await?;

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
                    let t = Topology::new(radius);

                    println!(
                        "Neighbourhood for overlay {} with radius {} is {}",
                        hex::encode(overlay),
                        radius,
                        t.get_neighbourhood(overlay)
                    );
                }
                OverlayCommands::AutoMine {
                    num_addresses,
                    network_id,
                    rpc,
                } => {
                    println!("Mining {} addresses...", num_addresses);

                    // First need to get the average storage radius
                    let client = Arc::new(Provider::<Http>::try_from(rpc)?);
                    let chain = crate::chain::ChainConfigWithMeta::new(client).await?;

                    let (avg_depth, sample_size) =
                        get_avg_depth(chain.get_address("REDISTRIBUTION").unwrap(), chain.client())
                            .await?;

                    println!(
                        "Average storage radius: {} (from {} samples)",
                        avg_depth, sample_size
                    );

                    // Set the topology to the rounded avg_depth
                    let t = Topology::new(avg_depth.round() as u32);

                    // Now we need to find the optimal neighbourhoods for the given radius
                    let mut game = Game::new(
                        chain.get_address("STAKE_REGISTRY").unwrap(),
                        chain.client(),
                        &t,
                    )
                    .await?;

                    let mut addresses = Vec::new();
                    let mut total_new_stake = U256::from(0);

                    loop {
                        let (r, n) = game.find_optimum_neighbourhood();

                        println!("Mining address into neighbourhood {} for radius {}", n, r);

                        let eth_address = MinedAddress::new(r, n, network_id, None)?;
                        let overlay_address = eth_address.overlay(network_id);

                        // a sanity check to make sure the mined address is in the correct
                        // neighbourhood
                        let t2 = Topology::new(r);
                        if t2.get_neighbourhood(overlay_address) != n {
                            println!(
                                "Neighbourhood for mined address: {}",
                                t2.get_neighbourhood(overlay_address)
                            );
                        }
                        assert!(t2.get_neighbourhood(overlay_address) == n);

                        addresses.push(overlay_address);

                        let new_player_stake =
                            game.neighbourhood_avg_stake(t.get_neighbourhood(overlay_address));
                        total_new_stake += new_player_stake;

                        // add the player to the game, using the neighbourhood's average stake
                        game.add_player(overlay_address, new_player_stake);

                        // Check that the mined address is in a neighbourhood with a population
                        // of 1
                        let neighbourhood = game.view_by_radius(Some(r), Some(n));
                        if neighbourhood.len() != 1 {
                            println!("Neighbourhood: {:?}", neighbourhood);
                        }
                        assert!(neighbourhood.len() == 1);

                        if addresses.len() == num_addresses as usize {
                            break;
                        }
                    }

                    game.stats();

                    println!("Total new stake: {} BZZ", total_new_stake);
                }
                OverlayCommands::ManualMine {
                    radius,
                    neighbourhood,
                    network_id,
                    nonce,
                } => {
                    let t = Topology::new(radius);
                    let mined_address =
                        MinedAddress::new(radius, neighbourhood, network_id, nonce)?;

                    println!(
                        "Mined overlay address: 0x{}",
                        hex::encode(mined_address.overlay(network_id))
                    );

                    println!(
                        "Neighbourhood for overlay {} with radius {} is {}",
                        hex::encode(mined_address.overlay(network_id)),
                        radius,
                        t.get_neighbourhood(mined_address.overlay(network_id))
                    );

                    println!(
                        "Ethereum address: 0x{}",
                        hex::encode(mined_address.address())
                    );
                    println!(
                        "Private key: 0x{}",
                        hex::encode(mined_address.private_key())
                    );
                    println!("Password: {}", mined_address.password());
                }
            }
        }
        Commands::Game {
            stake_registry,
            radius,
            rpc,
        } => {
            let client = Arc::new(Provider::<Http>::try_from(rpc)?);
            let chain = crate::chain::ChainConfigWithMeta::new(client).await?;
            let t = Topology::new(radius);

            let game = Game::new(
                stake_registry.unwrap_or(chain.get_address("STAKE_REGISTRY").unwrap()),
                chain.client(),
                &t,
            )
            .await?;

            game.stats();
        }
        Commands::PostageStamp {
            postage_stamp_contract_address,
            start_block,
            rpc,
        } => {
            let client = Arc::new(Provider::<Http>::try_from(rpc)?);
            let chain = crate::chain::ChainConfigWithMeta::new(client).await?;

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
        Commands::Wallet(args) => crate::wallet::process(args).await?,
    }

    Ok(())
}
