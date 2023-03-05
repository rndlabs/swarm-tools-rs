use ethers::prelude::{rand::Rng, *};
use eyre::Result;
use std::{collections::HashMap, sync::Arc};

use crate::{
    contracts::stake_registry::{StakeRegistry, StakeRegistryEvents},
    topology::Topology, Overlay,
};

const STAKEREGISTRY_START_BLOCK: u64 = 25527075;
const ROUND_LENGTH: u64 = 152;

struct Player {
    stake: U256,
}

pub struct Game {
    players: HashMap<Overlay, Player>,
    round_length: u64,
    depth: u32,
}

impl Game {
    pub async fn new(
        registry_address: H160,
        client: Arc<Provider<Http>>,
        store: &Topology,
    ) -> Result<Self> {
        // StakeRegistry contract
        let contract = StakeRegistry::new(registry_address, client.clone());

        let mut players: HashMap<Overlay, Player> = HashMap::new();

        // Subscribe to the StakeUpdated event
        let events = contract.events().from_block(STAKEREGISTRY_START_BLOCK);
        let logs = events.query().await?;

        // iterate over the events
        for log in logs.iter() {
            if let StakeRegistryEvents::StakeUpdatedFilter(f) = log {
                // get the overlay address
                let o = f.overlay;
                // get the stake
                let s = f.stake_amount;

                // add the overlay address and stake to the hashmap if the stake is greater than 0
                // if the overlay address already exists, add the new stake to the existing stake
                if !s.is_zero() {
                    players
                        .entry(o)
                        .and_modify(|e| e.stake += s)
                        .or_insert(Player { stake: s });
                }
            }
        }

        Ok(Self {
            players,
            round_length: ROUND_LENGTH,
            depth: store.depth,
        })
    }

    /// Return a vector of tuples containing the overlay address, stake, and neighbourhood of each player in the game.
    /// The vector is sorted by overlay address and optionally filtered by neighbourhood.
    pub fn view_by_radius(
        &self,
        radius: Option<u32>,
        target: Option<u32>,
    ) -> Vec<(Overlay, U256, u32)> {
        let mut players: Vec<(Overlay, U256, u32)> = Vec::new();
        let store = Topology::new(radius.unwrap_or(self.depth));

        for (o, p) in self.players.iter() {
            if p.stake > U256::from(0) {
                players.push((*o, p.stake, store.get_neighbourhood(*o)));
            }
        }

        // sort the vector by overlay address
        players.sort_by(|a, b| a.0.cmp(&b.0));

        // if a target neighbourhood is specified, filter the players by neighbourhood
        if let Some(target) = target {
            players.retain(|(_, _, n)| *n == target);
        }

        players
    }

    /// Given a radius, return a vector of tuples containing the neighbourhood and population.
    /// The vector is sorted ascending by population and optionally filtered by neighbourhood range.
    pub fn view_by_neighbourhood_population(
        &self,
        radius: Option<u32>,
        filter: Option<(u32, u32)>,
    ) -> Vec<(u32, u32)> {
        let t = Topology::new(radius.unwrap_or(8));

        // Create a hashmap to hold the neighbourhoods and their population
        let mut neighbourhoods: HashMap<u32, u32> = HashMap::new();

        // Get the view of the game by radius
        let view = self.view_by_radius(radius, None);

        // Iterate over the view and count the number of players in each neighbourhood
        for (_, _, n) in view {
            match filter {
                Some((lower, upper)) => {
                    if n < lower || n >= upper {
                        continue;
                    }
                }
                None => (),
            }
            neighbourhoods
                .entry(n)
                .and_modify(|e| *e += 1)
                .or_insert(1);
        }

        // Convert the hashmap to a vector
        let mut neighbourhoods: Vec<(u32, u32)> = neighbourhoods.into_iter().collect();

        // Fill in any missing neighbourhoods with a population of 0
        // This is necessary because the neighbourhoods are not necessarily contiguous
        // And apply the filter if one is specified
        for n in 0..t.num_neighbourhoods() {
            match filter {
                Some((lower, upper)) => {
                    if n < lower || n >= upper {
                        continue;
                    }
                }
                None => (),
            }
            if !neighbourhoods.iter().any(|(nn, _)| *nn == n) {
                neighbourhoods.push((n, 0));
            }
        }

        // Sort the vector by population
        neighbourhoods.sort_by(|a, b| a.1.cmp(&b.1));

        neighbourhoods
    }

    /// Given a radius, return a vector of tuples containing the neighbourhood and population.
    /// The range of neighbourhoods to analyze is optionally specified by a filter.
    pub fn lowest_population_neighbourhoods(
        &self,
        radius: Option<u32>,
        filter: Option<(u32, u32)>,
    ) -> (u32, Vec<u32>) {
        let neighbourhoods = self.view_by_neighbourhood_population(radius, filter);

        let mut lowest_neighbourhoods: Vec<u32> = Vec::new();

        // Iterate over the neighbourhoods and add the neighbourhoods with the lowest population to the vector
        for (n, population) in &neighbourhoods {
            if population == &neighbourhoods[0].1 {
                lowest_neighbourhoods.push(*n);
            }

            // If the population is greater than the lowest population, break out of the loop because the vector is sorted
            if population > &neighbourhoods[0].1 {
                break;
            }
        }

        (neighbourhoods[0].1, lowest_neighbourhoods)
    }

    /// A recursive function that finds the optimum neighbourhood to place a new player.
    /// The optimum neighbourhood is the neighbourhood with the lowest population.
    ///
    /// 1. Get the lowest population neighbourhoods.
    /// 2. If there is a tie, choose a random neighbourhood from the set of lowest population neighbourhoods.
    /// 3. Recursively call the function with increasing radius until a neighbourhood is found with a population of 0.
    pub fn find_optimum_neighbourhood_recurse(
        &self,
        radius: Option<u32>,
        filter: Option<(u32, u32)>,
    ) -> (u32, u32) {
        let (population, neighbourhoods) = self.lowest_population_neighbourhoods(radius, filter);

        // If there is a tie, choose a random neighbourhood from the set of lowest population neighbourhoods
        let n = match neighbourhoods.len() > 1 {
            false => neighbourhoods[0],
            true => {
                let mut rng = rand::thread_rng();
                neighbourhoods[rng.gen_range(0..neighbourhoods.len())]
            }
        };

        // If the population is 0, return the neighbourhood
        if population == 0 {
            (radius.unwrap(), n)
        } else {
            // If the population is not 0, recursively call the function with an increasing radius.
            // As the radius increases, the number of neighbourhoods increases exponentially.
            // Therefore we use a range to specify the neighbourhoods to analyze.
            // The range is calculated as follows:
            // - The lower bound is 2 * n where n is the current radius
            // - The upper bound is 2 * (n + 1) where n is the current radius
            // This is due to the nature that the number of neighbourhoods doubles with each increase in radius.
            self.find_optimum_neighbourhood_recurse(
                Some(radius.unwrap() + 1),
                Some((2 * n, (2 * (n + 1)))),
            )
        }
    }

    /// Given the current depth, find the optimum neighbourhood by recursively calling the function with increasing radius.
    /// The optimum neighbourhood is the neighbourhood with the lowest population.
    /// Returns a tuple containing the radius and neighbourhood.
    pub fn find_optimum_neighbourhood(&self) -> (u32, u32) {
        self.find_optimum_neighbourhood_recurse(Some(self.depth), None)
    }

    /// Print the game stats
    pub fn stats(&self) {
        let view = self.view_by_radius(Some(self.depth), None);

        let store = Topology::new(self.depth);
        let num_neighbourhoods = store.num_neighbourhoods();

        // Do statistical analysis per neighbourhood. Calculate:
        // - total number of players
        // - total stake
        // - average stake

        println!("Neighbourhood stats:");
        for neighbourhood in 0..num_neighbourhoods {
            let mut total_stake = U256::from(0);
            let mut total_players = 0;

            for (_, stake, r) in view.iter() {
                if *r == neighbourhood {
                    total_stake += *stake;
                    total_players += 1;
                }
            }

            // guard against division by zero
            match total_players == 0 {
                true => println!(
                    "Neighbourhood {}/{}: 0 players",
                    neighbourhood,
                    num_neighbourhoods - 1
                ),
                false => {
                    println!(
                        "Neighbourhood {}/{}: {} players, total stake: {}, avg stake: {}",
                        neighbourhood,
                        num_neighbourhoods - 1,
                        total_players,
                        total_stake,
                        total_stake / U256::from(total_players)
                    );
                }
            }
        }

        println!("{}", self);

        let mut total_stake = U256::from(0);
        let mut total_players = 0;
        let mut neighbourhoods: HashMap<u32, u32> = HashMap::new();

        for (_, stake, neighbourhood) in view {
            total_stake += stake;
            total_players += 1;

            *neighbourhoods.entry(neighbourhood).or_insert(0) += 1;
        }

        println!("Total players: {}", total_players);
        println!("Total stake: {}", total_stake);
        println!("Average stake: {}", total_stake / U256::from(total_players));
        println!(
            "Average neighbourhood population: {}",
            total_players / num_neighbourhoods
        );

        println!(
            "Lowest neighbourhoods: {:?}",
            self.lowest_population_neighbourhoods(None, None)
        );

        println!(
            "Optimum neighbourhood: {:?}",
            self.find_optimum_neighbourhood()
        );
    }
}

impl std::fmt::Display for Game {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let view = self.view_by_radius(Some(self.depth), None);

        writeln!(f, "overlay,stake,neighbourhood")?;
        for (overlay, stake, neighbourhood) in view {
            writeln!(f, "{},{:?},{}", hex::encode(overlay), stake, neighbourhood)?;
        }

        Ok(())
    }
}
