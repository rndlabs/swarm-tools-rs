pub struct Topology {
    pub depth: u32,
}

impl Topology {
    /// Create a new Topology instance
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
        match self.depth == 0 {
            true => 1,
            false => 2u32.pow(self.depth),
        }
    }

    /// Calculate a bit-mask for a given depth
    /// The bit-mask is a 256 bit value, with the first `depth` bits being 1, and the rest being 0
    pub fn neighbourhood_bitmask(&self) -> [u8; 32] {
        // create a bytes array to hold the bit-mask
        let mut bit_mask = [0u8; 32];

        // set the first `depth` bits to 1 (the rest are already 0)
        // store with the most significant bit first
        // so the first bit is at index 0, the second bit is at index 1, etc
        for i in 0..self.depth {
            bit_mask[i as usize / 8] |= 1 << (7 - (i % 8));
        }

        // return the bit-mask
        bit_mask
    }

    /// Calculate the neighbourhood for a given overlay address
    pub fn get_neighbourhood(&self, overlay_address: [u8; 32]) -> u32 {
        // Get the first 4 bytes of the overlay address as a u32 big endian
        let mut neighbourhood = [0u8; 4];
        neighbourhood.copy_from_slice(&overlay_address[0..4]);

        u32::from_be_bytes(neighbourhood) / self.neighbourhood_size()
    }

    /// Calculate the size of a neighbourhood for a given depth
    pub fn neighbourhood_size(&self) -> u32 {
        if self.depth == 0 {
            todo!("What to do if the depth is 0?")
        } else {
            (2u64.pow(32) / 2u64.pow(self.depth)).try_into().unwrap()
        }
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
