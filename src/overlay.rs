use ethers::{prelude::k256::ecdsa::SigningKey, prelude::*, types::H160, utils::keccak256};
use eyre::{anyhow, Result};

use crate::{topology::Topology, wallet::WalletStore};

pub type Nonce = [u8; 32];

pub trait OverlayCalculator {
    fn overlay_address(&self, network_id: u32, nonce: Option<Nonce>) -> crate::OverlayAddress;
}

impl OverlayCalculator for H160 {
    fn overlay_address(&self, network_id: u32, nonce: Option<Nonce>) -> crate::OverlayAddress {
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

        let path = std::env::current_dir()?.join("bees");

        let mut wallet_store = WalletStore::load(path)?;

        // get the base overlay address for the target neighbourhood and depth
        let base_overlay_address = t.get_base_overlay_address(neighbourhood);

        // calculate the bit-mask for the depth
        let bit_mask = t.neighbourhood_bitmask();

        // create a temporary directory to store the keystore
        let dir = tempfile::tempdir()?;
        let path = dir.path();

        let mut count = 0;

        loop {
            // increment the count
            count += 1;

            // Create a new keystore
            let result = wallet_store.create_wallet(
                &path,
                None,
                |key| {
                    // calculate the overlay address for the keypair
                    let overlay_address = key.address().overlay_address(network_id, nonce);

                    // return the hex-encoded overlay address
                    hex::encode(overlay_address)
                },
                |key| {
                    // calculate the overlay address for the keypair
                    let overlay_address = key.address().overlay_address(network_id, nonce);

                    // use the bit mask to compare the overlay address to the base overlay address
                    for i in 0..32 {
                        if overlay_address[i] & bit_mask[i] != base_overlay_address[i] & bit_mask[i] {
                            return false;
                        }
                    }

                    true
                },
            );

            match result {
                Ok((wallet, password)) => {
                    // print diagnostics
                    println!("Overlay address: {}", hex::encode(wallet.address().overlay_address(network_id, nonce)));
                    println!("Base address: {}", hex::encode(base_overlay_address));
                    println!("Bitmask: {}", hex::encode(bit_mask));
                    // if a match was found, print the keypair and exit
                    println!("Match found after {} iterations...", count);

                    dir.close()?;

                    return Ok(Self {
                        wallet,
                        nonce,
                        password,
                    });
                }
                Err(e) => {
                    // if the error is "Wallet verification failed", then we just need to try again
                    if e.to_string().contains("Wallet verification failed") {
                        continue;
                    }

                    // bubble the error up
                    return Err(e);
                }
            }
        }
    }

    pub fn wallet(&self) -> &Wallet<SigningKey> {
        &self.wallet
    }

    pub fn overlay(&self, network_id: u32) -> crate::OverlayAddress {
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
