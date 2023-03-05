use ethers::prelude::*;
use eyre::Result;
use std::sync::Arc;

use crate::{
    contracts::{
        redistribution::{Redistribution, RedistributionEvents},
    },
};

pub async fn get_avg_depth(
    redistribution_address: H160,
    client: Arc<Provider<Http>>,
) -> Result<(f64, u32)> {
    // Redistribution contract
    let contract = Redistribution::new(redistribution_address, client.clone());

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
