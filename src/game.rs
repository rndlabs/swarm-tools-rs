use ethers::prelude::{rand::Rng, *};
use eyre::Result;
use std::collections::HashMap;

use crate::{
    chain::ChainConfigWithMeta,
    contracts::stake_registry::{StakeRegistry, StakeRegistryEvents},
    redistribution::get_avg_depth,
    topology::Topology,
    OverlayAddress,
};

const STAKEREGISTRY_START_BLOCK: u64 = 25527075;
const ROUND_LENGTH: u64 = 152;

struct Player {
    stake: U256,
}

pub struct Game {
    players: HashMap<OverlayAddress, Player>,
    round_length: u64,
    topology: Topology,
}

impl Game {
    pub async fn load<M>(chain: &ChainConfigWithMeta<M>, topology: Option<Topology>) -> Result<Self>
    where
        M: Middleware + Clone + 'static,
    {
        // If a topology is not provided, calculate the topology from the average depth of the swarm.
        let topology = match topology {
            Some(t) => t,
            None => {
                let (avg_depth, _) =
                    get_avg_depth(chain.get_address("REDISTRIBUTION")?, chain.clone()).await?;

                Topology::new((avg_depth.round() as u64).try_into()?)
            }
        };

        // StakeRegistry contract
        let contract = StakeRegistry::new(chain.get_address("STAKE_REGISTRY")?, chain.client());

        let mut players: HashMap<OverlayAddress, Player> = HashMap::new();

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
            topology,
        })
    }

    pub fn add_player(&mut self, o: OverlayAddress, s: U256) {
        // add the overlay address and stake to the hashmap if the stake is greater than 0
        // if the overlay address already exists, add the new stake to the existing stake
        if !s.is_zero() {
            self.players
                .entry(o)
                .and_modify(|e| e.stake += s)
                .or_insert(Player { stake: s });
        }
    }

    /// Generate a view of the game given a storage radius
    /// Returns a vector of tuples containing (overlay, stake, neighbourhood) for each player in the game.
    /// The vector is sorted by overlay address and optionally filtered by neighbourhood.
    pub fn view_by_radius(
        &self,
        radius: Option<u32>,
        target: Option<u32>,
    ) -> Vec<(OverlayAddress, U256, u32)> {
        let mut players: Vec<(OverlayAddress, U256, u32)> = Vec::new();
        let t = radius.map(Topology::new).unwrap_or(self.topology.clone());

        for (o, p) in self.players.iter() {
            if p.stake > U256::from(0) {
                players.push((*o, p.stake, t.get_neighbourhood(*o)));
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

    /// Calculate the average stake of all players in a neighbourhood at the calculated radius.
    pub fn neighbourhood_avg_stake(&self, n: u32) -> U256 {
        let mut total_stake = U256::from(0);
        let mut num_players = 0;

        for (_, stake, _) in self.view_by_radius(None, Some(n)) {
            total_stake += stake;
            num_players += 1;
        }

        match num_players {
            0 => U256::from(0),
            _ => total_stake / U256::from(num_players),
        }
    }

    /// Generate a view of the game by neighbourhood and population.
    /// Returns a vector of tuples containing (neighbourhood, population) for each neighbourhood in the game.
    /// The vector is sorted ascending by population and optionally filtered by neighbourhood range.
    /// The neighbourhoods are not necessarily contiguous and any missing neighbourhoods are filled in with a population of 0.
    /// The filter range is inclusive of the lower bound and exclusive of the upper bound.
    pub fn view_by_neighbourhood_population(
        &self,
        radius: Option<u32>,
        filter: Option<(u32, u32)>,
    ) -> Vec<(u32, u32)> {
        let t = radius.map(Topology::new).unwrap_or(self.topology.clone());

        // Create a hashmap to hold the neighbourhoods and their population
        let mut neighbourhoods: HashMap<u32, u32> = HashMap::new();

        // Get the view of the game by radius
        let view = self.view_by_radius(radius, None);

        // Iterate over the view and count the number of players in each neighbourhood
        for (_, _, n) in view {
            if let Some((lower, upper)) = filter {
                if n < lower || n >= upper {
                    continue;
                }
            }
            neighbourhoods.entry(n).and_modify(|e| *e += 1).or_insert(1);
        }

        // Convert the hashmap to a vector
        let mut neighbourhoods: Vec<(u32, u32)> = neighbourhoods.into_iter().collect();

        // Fill in any missing neighbourhoods with a population of 0
        // This is necessary because the neighbourhoods are not necessarily contiguous
        for n in 0..t.num_neighbourhoods() {
            // Skip the neighbourhood if it is outside the filter range
            if let Some((lower, upper)) = filter {
                if n < lower || n >= upper {
                    continue;
                }
            }
            // If the neighbourhood is not in the vector, add it with a population of 0
            if !neighbourhoods.iter().any(|(nn, _)| *nn == n) {
                neighbourhoods.push((n, 0));
            }
        }

        // Sort the vector by population
        neighbourhoods.sort_by(|a, b| a.1.cmp(&b.1));

        neighbourhoods
    }

    /// Generate a view of the game by neighbourhood with the lowest population.
    /// Returns a tuple containing the population and a vector of neighbourhoods with the lowest population.
    /// The vector is sorted ascending by neighbourhood and optionally filtered by neighbourhood range.
    pub fn lowest_population_neighbourhoods(
        &self,
        radius: Option<u32>,
        filter: Option<(u32, u32)>,
    ) -> (u32, Vec<u32>) {
        let neighbourhoods = self.view_by_neighbourhood_population(radius, filter);

        let mut lowest_neighbourhoods: Vec<u32> = Vec::new();

        // As the vector is sorted by population, the first neighbourhood in the vector will have the lowest population
        let lowest = neighbourhoods[0].1;

        // Iterate over the neighbourhoods and add the neighbourhoods with the lowest population to the vector
        // Break out of the loop when the population is no longer the lowest
        for (n, population) in &neighbourhoods {
            match *population == lowest {
                true => lowest_neighbourhoods.push(*n),
                false => break,
            }
        }

        (lowest, lowest_neighbourhoods)
    }

    /// Given a vector of overlays, calculate what to stake for each overlay.
    pub fn calculate_funding(
        &self,
        radius: Option<u32>,
        overlays: &Vec<OverlayAddress>,
        max_bzz: Option<U256>,
    ) -> Vec<(OverlayAddress, U256)> {
        let mut funding_table: Vec<(OverlayAddress, U256)> = Vec::new();

        let t = radius.map(Topology::new).unwrap_or(self.topology.clone());

        for o in overlays {
            let neighbourhood = t.get_neighbourhood(*o);
            let avg_stake = self.neighbourhood_avg_stake(neighbourhood);
            funding_table.push((*o, max_bzz.unwrap_or(avg_stake)));
        }

        // sort the vector by overlay address
        funding_table.sort_by(|a, b| a.0.cmp(&b.0));

        funding_table
    }

    /// A recursive function that finds the optimum neighbourhood to place a new player.
    /// The optimum neighbourhood is the neighbourhood with the lowest population.
    ///
    /// 1. Get the lowest population neighbourhoods.
    /// 2. If there is a tie, choose a random neighbourhood from the set of lowest population neighbourhoods.
    /// 3. Recursively call the function with increasing radius until a neighbourhood is found with a population of 0.
    pub fn find_optimum_neighbourhood_recurse(
        &self,
        radius: u32,
        filter: Option<(u32, u32)>,
    ) -> (u32, u32) {
        let (population, neighbourhoods) =
            self.lowest_population_neighbourhoods(Some(radius), filter);

        // If there is a tie, choose a random neighbourhood from the set of lowest population neighbourhoods
        let n = match neighbourhoods.len() > 1 {
            false => neighbourhoods[0],
            true => {
                let mut rng = rand::thread_rng();
                neighbourhoods[rng.gen_range(0..neighbourhoods.len())]
            }
        };

        // If the population is 0, return the neighbourhood
        // If the population is not 0, recursively call the function with an increasing radius.
        // As the radius increases, the number of neighbourhoods increases exponentially.
        // Therefore we use a range to specify the neighbourhoods to analyze.
        // The range is calculated as follows:
        // - The lower bound is 2 * n where n is the current radius
        // - The upper bound is 2 * (n + 1) where n is the current radius
        // This is due to the nature that the number of neighbourhoods doubles with each increase in radius.
        match population {
            0 => (radius, n),
            _ => self.find_optimum_neighbourhood_recurse(radius + 1, Some((2 * n, (2 * (n + 1))))),
        }
    }

    /// Find the optimum neighbourhood for inserting a new player.
    /// The optimum neighbourhood is the neighbourhood with the lowest population.
    /// Returns a tuple containing the radius and neighbourhood.
    pub fn find_optimum_neighbourhood(&self) -> (u32, u32) {
        self.find_optimum_neighbourhood_recurse(self.topology.depth, None)
    }

    /// Print the game stats
    pub fn stats(&self) {
        let view = self.view_by_radius(None, None);

        let num_neighbourhoods = self.topology.num_neighbourhoods();

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
        let view = self.view_by_radius(Some(self.topology.depth), None);

        writeln!(f, "overlay,stake,neighbourhood")?;
        for (overlay, stake, neighbourhood) in view {
            writeln!(f, "{},{:?},{}", hex::encode(overlay), stake, neighbourhood)?;
        }

        Ok(())
    }
}
