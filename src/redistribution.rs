use eyre::Result;
use std::{collections::HashMap, sync::Arc};

use crate::{
    contracts::{
        redistribution::{Redistribution, RedistributionEvents},
        stake_registry::{StakeRegistry, StakeRegistryEvents},
    },
    topology::Topology,
};
use ethers::prelude::*;

const STAKEREGISTRY_START_BLOCK: u64 = 25527075;

pub async fn get_avg_depth(
    redistribution_address: H160,
    client: Arc<Provider<Http>>,
) -> Result<(f64, u32)> {
    // Redistribution contract
    let contract = Redistribution::new(redistribution_address, Arc::clone(&client));

    // Get the current block number
    let block_number = client.get_block_number().await?;

    // Block time is 5 seconds, so start the block at 1 day ago
    let start_block = block_number - 60 * 60 * 24 / 5;

    // Subscribe to the StakeUpdated event
    let events = contract.events().from_block(start_block);
    let logs = events.query().await?;

    let mut avg_depth: usize = 0;
    let mut count = 0;

    // iterate over the events
    for log in logs.iter() {
        if let RedistributionEvents::TruthSelectedFilter(f) = log {
            // add the depth to the average
            avg_depth += f.depth as usize;
            // count the number of truths
            count += 1;
        }
    }

    // calculate the average
    Ok((avg_depth as f64 / count as f64, count as u32))
}

/// Get all the stakes from the contract. Returns a vector of tuples containing:
/// 1. the overlay address
/// 2. the stake
/// 3. the neighbourhood
/// The vector is sorted by overlay address
async fn get_all_stakes(
    registry_address: H160,
    client: Arc<Provider<Http>>,
    store: &Topology,
) -> Result<Vec<([u8; 32], U256, u32)>> {
    // StakeRegistry contract
    let contract = StakeRegistry::new(registry_address, Arc::clone(&client));

    // Create a hashmap to hold the overlay addresses and stakes
    let mut stakes: HashMap<[u8; 32], U256> = HashMap::new();

    // Subscribe to the StakeUpdated event
    let events = contract.events().from_block(STAKEREGISTRY_START_BLOCK);
    let logs = events.query().await?;

    // iterate over the events
    for log in logs.iter() {
        if let StakeRegistryEvents::StakeUpdatedFilter(f) = log {
            // get the overlay address
            let overlay = f.overlay;
            // get the stake
            let stake = f.stake_amount;

            // add the overlay address and stake to the hashmap if the stake is greater than 0
            // if the overlay address already exists, add the new stake to the existing stake
            if !stake.is_zero() {
                stakes
                    .entry(overlay)
                    .and_modify(|e| *e += stake)
                    .or_insert(stake);
            }
        }
    }

    // create a vector to hold the overlay addresses and stakes
    let mut stakes_vec: Vec<([u8; 32], U256, u32)> = Vec::new();

    // iterate over the hashmap and add the overlay addresses and stakes to the vector
    for (overlay_address, stake) in stakes {
        stakes_vec.push((
            overlay_address,
            stake,
            store.get_neighbourhood(overlay_address),
        ));
    }

    // sort the vector by overlay address
    stakes_vec.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(stakes_vec)
}

pub async fn dump_stats(
    address: H160,
    client: Arc<Provider<Http>>,
    store: &Topology,
) -> Result<()> {
    println!("Schelling game stake distribution statistics");

    // dump all the stakes
    let stakes = get_all_stakes(address, client.clone(), store)
        .await
        .unwrap();

    // number of neighbourhoods
    let num_neighbourhoods = store.num_neighbourhoods();

    println!();
    println!("overlay,stake,neighbourhood");

    // print all the stakes iterating over by specific index
    for stake in &stakes {
        println!(
            "0x{},{},{}",
            hex::encode(stake.0), // overlay
            stake.1,              // stake
            stake.2               // neighbourhood
        );
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
    for stake in &stakes {
        // add the stake to the total stakes for the neighbourhood
        total_stakes[stake.2 as usize] += stake.1;
        // increment the number of overlay addresses for the neighbourhood
        num_overlay_addresses[stake.2 as usize] += 1;
    }

    println!();

    // print the total stakes per neighbourhood
    println!("Total stakes per neighbourhood:");
    for i in 0..num_neighbourhoods {
        println!(
            "Neighbourhood {}/{}: {}",
            i,
            num_neighbourhoods - 1,
            total_stakes[i as usize]
        );
    }

    println!();

    // print the average stakes per neighbourhood
    println!("Average stakes per neighbourhood:");
    for i in 0..num_neighbourhoods {
        // guard against divide by zero
        if num_overlay_addresses[i as usize] == 0 {
            println!("Neighbourhood {}/{}: 0", i, num_neighbourhoods);
            continue;
        }
        println!(
            "Neighbourhood {}/{}: {}",
            i,
            num_neighbourhoods - 1,
            total_stakes[i as usize] / U256::from(num_overlay_addresses[i as usize])
        );
    }

    println!();
    println!("Summary:");

    // print the total number of overlay addresses per neighbourhood
    println!("Total number of overlay addresses per neighbourhood:");
    for i in 0..num_neighbourhoods {
        println!(
            "Neighbourhood {}/{}: {}",
            i,
            num_neighbourhoods - 1,
            num_overlay_addresses[i as usize]
        );
    }

    // print the total number of overlay addresses
    println!("Total number of overlay addresses: {}", stakes.len());

    // print the total stake
    let mut total_stake = U256::zero();
    for stake in total_stakes {
        total_stake += stake;
    }
    println!("Total stake: {} BZZ", total_stake);

    // print the average stake
    println!(
        "Average stake: {} BZZ",
        total_stake / U256::from(stakes.len())
    );

    Ok(())
}
