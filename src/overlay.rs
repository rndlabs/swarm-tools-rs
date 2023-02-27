use ethers::{types::H160, utils::keccak256};

pub trait Overlay {
    fn overlay_address(&self, network_id: u32, nonce: Option<[u8; 32]>) -> [u8; 32];
}

impl Overlay for H160 {
    fn overlay_address(&self, network_id: u32, nonce: Option<[u8; 32]>) -> [u8; 32] {
        // get the public key of the signer
        // this will be 256 bits for the public key, 64 bits for the network id, and 256 bits for the nonce
        let mut data = [0u8; 20 + 8 + 32];
        // copy the public key into the first 32 bytes
        data[0..20].copy_from_slice(self.as_bytes());
        // copy the network id into the next 8 bytes
        data[24..28].copy_from_slice(&network_id.to_le_bytes());
        // copy the nonce into the last 32 bytes
        let nonce = nonce.unwrap_or([0u8; 32]);
        data[28..60].copy_from_slice(&nonce);

        // return the hash
        keccak256(data)
    }
}
