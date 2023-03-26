use clap::{Args, Parser, Subcommand};
use ethers::types::{H160, U256};
use eyre::Result;

use swarm_tools::{
    game::Game,
    overlay::{MinedAddress, Overlay},
    parse_bytes32, parse_name_or_address,
    postage::PostOffice,
    redistribution::get_avg_depth,
    topology::Topology, chain::Chain,
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
                    let chain = Chain::new(rpc).await?;

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

                    loop {
                        let (r, n) = game.find_optimum_neighbourhood();

                        println!(
                            "Mining address into neighbourhood {} for radius {}",
                            n, r
                        );

                        let address = MinedAddress::new(r, n, network_id, None)?;

                        addresses.push(address.overlay(network_id));

                        // add to the game
                        game.add_player(address.overlay(network_id), U256::from(1));

                        if addresses.len() == num_addresses as usize {
                            break;
                        }
                    }

                    game.stats();
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
            let chain = swarm_tools::chain::Chain::new(rpc).await?;
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
