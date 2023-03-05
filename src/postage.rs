use ethers::prelude::*;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

use crate::contracts::postage_stamp::{PostageStamp, PostageStampEvents};

pub type ID = [u8; 32];
const BLOCK_TIME: u64 = 5;

#[derive(Serialize, Deserialize, Debug)]
pub struct Batch {
    id: ID,             // batch id
    value: U256,        // normalised balance of the batch
    start: u64,         // block number when the batch was created
    owner: H160,        // owner of the batch
    depth: u8,          // batch depth, i.e., size = 2^{depth}
    bucket_depth: u8,   // the depth of the neighbourhoods t
    immutable: bool,    // if the batch allows adding new capacity (dilution)
    storage_radius: u8, // storage radius
    created: u64,       // the unix timestamp when the batch was created
}

impl Batch {
    /// Based on the current price and the cumulative payout, calculate the time to live (ttl) of the batch.
    pub fn ttl(&self, cumulative_payout: U256, price: U256) -> u64 {
        let ttl = self.value - cumulative_payout;
        let ttl = ttl * BLOCK_TIME;
        let ttl = ttl / price;

        ttl.as_u64()
    }

    /// Based on the current price and the cumulative payout, calculate the expiry of the batch.
    pub fn expiry(&self, cumulative_payout: U256, price: U256) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now + self.ttl(cumulative_payout, price);

        expiry
    }

    /// Calculate the size of the batch in chunks.
    pub fn size_chunks(&self) -> u64 {
        let num_chunks = 2_u64.pow(self.depth as u32);
        num_chunks
    }

    /// Calculate the size of the batch in bytes.
    pub fn size_bytes(&self) -> u64 {
        let bytes = self.size_chunks() * 4096;
        bytes
    }
}

pub struct PostOffice {
    batches: HashMap<ID, Batch>,
    price: U256,
    current_total_out_payment: U256,
}

impl PostOffice {
    /// Get all the current batches from the contract and the current price.
    pub async fn new(
        postage_stamp_contract_address: H160,
        client: Arc<Provider<Http>>,
        start_block: u64,
    ) -> Result<Self> {
        // Batch contract
        let contract = PostageStamp::new(postage_stamp_contract_address, Arc::clone(&client));

        // Create a hashmap to hold the overlay addresses and stakes
        let mut batches: HashMap<ID, Batch> = HashMap::new();

        // Subscribe to the BatchCreated event
        let events = contract.events().from_block(start_block);
        let logs = events.query_with_meta().await?;

        // count the number of events
        let num_events = logs.len();
        println!("Found {} events. This may take a while...", num_events);

        let mut i = 0;

        // iterate over the events
        for log in logs.iter() {
            match log {
                (PostageStampEvents::BatchCreatedFilter(f), meta) => {
                    // get the batch id
                    let id = f.batch_id;
                    // get the batch value
                    let value = f.normalised_balance;
                    // get the batch start
                    let start = meta.block_number.as_u64();
                    // get the batch owner
                    let owner = f.owner;
                    // get the batch depth
                    let depth = f.depth;
                    // get the batch bucket depth
                    let bucket_depth = f.bucket_depth;
                    // get the batch immutable
                    let immutable = f.immutable_flag;
                    // get the batch storage radius
                    let storage_radius = 0;
                    // get the time the batch was created
                    let created = client
                        .get_block(meta.block_number)
                        .await
                        .unwrap()
                        .unwrap()
                        .timestamp
                        .as_u64();

                    // add the batch to the hashmap
                    batches.insert(
                        id,
                        Batch {
                            id,
                            value,
                            start,
                            owner,
                            depth,
                            bucket_depth,
                            immutable,
                            storage_radius,
                            created,
                        },
                    );
                }
                (PostageStampEvents::BatchTopUpFilter(f), _) => {
                    // get the batch id
                    let id = f.batch_id;
                    // get the batch value
                    let value = f.normalised_balance;

                    // add the batch to the hashmap
                    batches.entry(id).and_modify(|e| e.value = value);
                }
                (PostageStampEvents::BatchDepthIncreaseFilter(f), _) => {
                    // get the batch id
                    let id = f.batch_id;
                    // get the batch depth
                    let depth = f.new_depth;
                    // get the normalised balance
                    let value = f.normalised_balance;

                    // add the batch to the hashmap
                    batches.entry(id).and_modify(|e| {
                        e.depth = depth;
                        e.value = value;
                    });
                }
                _ => {}
            }

            i += 1;
            if i % 500 == 0 {
                println!("Processed {} PostageStamp events", i);
            }
        }

        // get the current total payout
        let current_total_out_payment = contract.current_total_out_payment().call().await?;

        // iterate over all items in the hashmap and drop the ones that have a value < current_total_out_payment
        batches.retain(|_, batch| batch.value >= current_total_out_payment);

        // get the current price
        let price = contract.last_price().call().await?;

        // create the PostOffice
        let post_office = PostOffice {
            batches,
            price,
            current_total_out_payment,
        };

        Ok(post_office)
    }

    /// Get the total number of chunks across all the batches.
    pub fn num_chunks(&self) -> u64 {
        let mut paid_chunks = 0;

        for batch in self.batches.values() {
            paid_chunks += batch.size_chunks();
        }

        paid_chunks
    }

    /// Get the total rewards (in atomic BZZ) for a given round length (in blocks).
    /// Recall that the `round reward = price * round_length * num_chunks`
    pub fn round_reward(&self, round_length: u64) -> U256 {
        self.price * U256::from(round_length) * U256::from(self.num_chunks())
    }
}

impl std::fmt::Display for PostOffice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // iterate over the batches and output id,chunks,bytes,ttl
        writeln!(f, "id,chunks,bytes,created,ttl,expiry")?;
        for (id, batch) in self.batches.iter() {
            writeln!(
                f,
                "{},{},{},{},{},{}",
                hex::encode(id),
                batch.size_chunks(),
                batch.size_bytes(),
                batch.created,
                batch.ttl(self.current_total_out_payment, self.price),
                batch.expiry(self.current_total_out_payment, self.price)
            )?;
        }

        Ok(())
    }
}
