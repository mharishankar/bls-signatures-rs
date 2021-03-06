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
    let message = &args[1];
    let messageHexDec = hex::decode(message).unwrap();

    let mut secret_key = hex::decode(&args[2]).unwrap();
    let mut agg_sig = Bn256.sign(&secret_key, &messageHexDec).unwrap();
    let mut agg_pub_key = Bn256.derive_public_key(&secret_key).unwrap();

    for n in 3..args.len() {
        secret_key = hex::decode(&args[n]).unwrap();
        let mut pub_key_2 = Bn256.derive_public_key(&secret_key).unwrap();
        let mut sig_2 = Bn256.sign(&secret_key, &messageHexDec).unwrap();
        agg_sig = Bn256.aggregate_signatures(&[&agg_sig, &sig_2]).unwrap();
        agg_pub_key = Bn256.aggregate_public_keys(&[&agg_pub_key, &pub_key_2]).unwrap();
    }
    let encoded = hex::encode(&agg_sig);
    println!("\nAggregated Signature In Hex of Length {} \n {:?}\n\n", encoded.len(), &encoded);

    println!("\nCompressed Public Key In Hex\n {:02X?}\n\n", &agg_pub_key);
    let pubKeyUncompVec = PublicKey::from_compressed(&agg_pub_key).unwrap().to_uncompressed().unwrap();
    let mut encoded = hex::encode(&pubKeyUncompVec[0..32]);
    println!("Uncompressed Public Key X Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[32..64]);
    println!("Uncompressed Public Key X Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[64..96]);
    println!("Uncompressed Public Key Y Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[96..128]);
    println!("Uncompressed Public Key Y Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    // Bn256.verify(&agg_sig, &messageHexDec, &agg_pub_key).unwrap();
    // println!("Successful verification");
}