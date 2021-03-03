use bls_signatures_rs::bn256::Bn256;
use bls_signatures_rs::MultiSignature;
use bls_signatures_rs::bn256::PublicKey;
use bn::{arith, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};
extern crate hex_slice;
use hex_slice::AsHex;
extern crate hex;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    let mut secret_key = hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();
    if (args.len() > 1) { 
        secret_key = hex::decode(&args[1]).unwrap();
    }
    // Derive public key from secret key
    let public_key = Bn256.derive_public_key(&secret_key).unwrap();
    println!("Compressed Public Key In Hex\n {:02X?}\n\n", &public_key);
    let pubKeyUncompVec = PublicKey::from_compressed(&public_key).unwrap().to_uncompressed().unwrap();
    let mut encoded = hex::encode(&pubKeyUncompVec[0..32]);
    println!("Uncompressed Public Key X Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[32..64]);
    println!("Uncompressed Public Key X Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[64..96]);
    println!("Uncompressed Public Key Y Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[96..128]);
    println!("Uncompressed Public Key Y Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
}
