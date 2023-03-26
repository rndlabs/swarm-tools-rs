use ethers::{prelude::k256::ecdsa::SigningKey, types::H160, utils::keccak256};
use eyre::{anyhow, Result};

use ethers::prelude::*;
use passwords::PasswordGenerator;

use crate::topology::Topology;

pub type Nonce = [u8; 32];

pub trait Overlay {
    fn overlay_address(&self, network_id: u32, nonce: Option<Nonce>) -> crate::Overlay;
}

impl Overlay for H160 {
    fn overlay_address(&self, network_id: u32, nonce: Option<Nonce>) -> crate::Overlay {
        // get the public key of the signer
        // this will be 256 bits for the public key, 64 bits for the network id, and 256 bits for the nonce
        let mut data = [0u8; 20 + 8 + 32];
        // copy the public key into the first 32 bytes
        data[0..20].copy_from_slice(self.as_bytes());
        // copy the network id into the next 8 bytes
        data[20..24].copy_from_slice(&network_id.to_le_bytes());
        // copy the nonce into the last 32 bytes
        let nonce = nonce.unwrap_or([0u8; 32]);
        data[28..60].copy_from_slice(&nonce);

        // return the hash
        keccak256(data)
    }
}

pub struct MinedAddress {
    wallet: Wallet<SigningKey>,
    nonce: Option<Nonce>,
    password: String,
}

impl MinedAddress {
    pub fn new(
        radius: u32,
        neighbourhood: u32,
        network_id: u32,
        nonce: Option<Nonce>,
    ) -> Result<Self> {
        let t = Topology::new(radius);

        // guard against invalid neighbourhoods
        if neighbourhood >= t.num_neighbourhoods() {
            return Err(anyhow!(
                "Invalid neighbourhood {} for radius {}. Max neighbourhood is {}",
                neighbourhood,
                radius,
                t.num_neighbourhoods() - 1
            ));
        }

        println!(
            "Mining overlay address for neighbourhood {}/{}",
            neighbourhood,
            t.num_neighbourhoods() - 1
        );

        // get the base overlay address for the target neighbourhood and depth
        let base_overlay_address = t.get_base_overlay_address(neighbourhood);

        // calculate the bit-mask for the depth
        let bit_mask = t.neighbourhood_bitmask();

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
            let (wallet, uuid) =
                LocalWallet::new_keystore(path, &mut rand::thread_rng(), password.clone(), None)?;

            // calculate the overlay address for the keypair
            let overlay_address = wallet.address().overlay_address(network_id, nonce);

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
                // if a match was found, print the keypair and exit
                println!("Match found after {} iterations...", count);

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
                    current_dir.join(format!("{}.password", hex::encode(overlay_address))),
                    password.clone(),
                )?;

                dir.close()?;

                return Ok(Self {
                    wallet,
                    nonce,
                    password,
                });
            }
        }
    }

    pub fn wallet(&self) -> &Wallet<SigningKey> {
        &self.wallet
    }

    pub fn overlay(&self, network_id: u32) -> crate::Overlay {
        self.wallet
            .address()
            .overlay_address(network_id, self.nonce)
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn address(&self) -> H160 {
        self.wallet.address()
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.wallet.signer().to_bytes().into()
    }
}

// Tests
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_overlay_address() {
        let address = H160::from_str("0xac485e3c63dcf9b4cda9f007628bb0b6fed1c063").unwrap();
        let network_id = 1;
        let nonce = [0u8; 32];
        let overlay_address = address.overlay_address(network_id, Some(nonce));

        // assert that the overlay address is correct
        assert_eq!(
            Vec::from(overlay_address),
            hex::decode("fe3a6d582c577404fb19df64a44e00d3a3b71230a8464c0dd34af3f0791b45f2")
                .unwrap()
        )
    }
}
