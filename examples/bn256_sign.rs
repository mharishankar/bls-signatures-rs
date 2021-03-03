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
    let secret_key = hex::decode(&args[2]).unwrap();
    let messageHexDec = hex::decode(message).unwrap();
    let sig = Bn256.sign(&secret_key, &messageHexDec).unwrap();
    println!("\nCompressed Signature\n {:?}\n\n", &sig);
    let encoded = hex::encode(&sig);
    println!("\nCompressed Signature In Hex of Length {} \n {:?}\n\n", encoded.len(), &encoded);
}
