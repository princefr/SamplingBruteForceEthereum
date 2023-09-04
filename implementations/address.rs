


use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};



#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Address(String);


impl Address {
    pub fn new(address: String) -> Self {
        Self(address)
    }


    pub fn extended_secret_key_to_string_private_key(secret_key: SecretKey) -> String {
       let private_key = secret_key.display_secret().to_string();
        return format!("0x{}", private_key);
    }


    pub fn extended_public_key_to_address(public_key: PublicKey) -> String {
        //format as uncompressed key, remove "04" in the beginning
        let pubk_uncomp = &bitcoin::PublicKey::new_uncompressed(public_key).to_string()[2..];
        //decode from hex and pass to keccak for hashing
        let pubk_bytes = hex::decode(pubk_uncomp).unwrap();
        let addr = &Address::keccak_hash(&pubk_bytes);
        //keep last 20 bytes of the result
        let addr = &addr[(addr.len() - 40)..];
        //massage into domain unit
        return format!("0x{}", addr);
    }

    fn keccak_hash<T>(data: &T) -> String
    where
    T: ?Sized + Serialize + AsRef<[u8]>,
{
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let hex_r = hex::encode(result);
    hex_r
}
}