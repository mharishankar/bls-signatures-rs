use bls_signatures_rs::bn256::Bn256;
use bls_signatures_rs::MultiSignature;
use bls_signatures_rs::bn256::PublicKey;
use bn::{arith, pairing_batch, AffineG1, AffineG2, Fq, Fq2, Fr, Group, Gt, G1, G2};
// use bytes::Bytes;
// use std::str;
extern crate hex_slice;
use hex_slice::AsHex;
extern crate hex;

fn main() {
    // Secret key
    let secret_key =
        hex::decode("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721").unwrap();

    // Derive public key from secret key
    let public_key = Bn256.derive_public_key(&secret_key).unwrap();

    println!("\nCompressed Public Key\n {:?}\n\n", &public_key);
    println!("\nCompressed Public Key In Hex\n {:02X?}\n\n", &public_key);
    let g2 = G2::from_compressed(&public_key).unwrap();
    println!("Uncompressed Public Key in Coords\n {:?}\n\n", &g2);
    let pubKeyUncompVec = PublicKey::from_compressed(&public_key).unwrap().to_uncompressed().unwrap();
    println!("Uncompressed Public Key with {} elements\n {:?}\n\n", pubKeyUncompVec.len(), &pubKeyUncompVec);
    let mut encoded = hex::encode(&pubKeyUncompVec[0..32]);
    println!("Uncompressed Public Key X Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[32..64]);
    println!("Uncompressed Public Key X Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[64..96]);
    println!("Uncompressed Public Key Y Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&pubKeyUncompVec[96..128]);
    println!("Uncompressed Public Key Y Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);

    let message = "a9d924e432c2bfca01fa8048f99b3bbacfd9d903a242e3e6b1933833652bbe48ab312385022e2835e3f6a6dba201c47d6c6801796cda21120607c715ca95c13b1fadb75252c5c536009f3bd72bfb398dae0bdfc82493826ffc38a264a7d47376045115ebc7f7b978c02cd23e609077b1d8c6e73e51159e7bf98ec69fb0bebba7128f731a6a0c284bbead710fa8059746ce3effdc7e59257fc5ade51b9e60b62227bae2c16607c1428f8fc8eec7925fb0d7b6cc0e806c857b9cfb54aba0b9e026";
    let messageHexDec = hex::decode(message).unwrap();
    let msgG1Point = Bn256.hash_to_try_and_increment(&messageHexDec).unwrap();
    let msgG1PointInHex = Bn256.to_uncompressed_g1(msgG1Point).unwrap();
    encoded = hex::encode(&msgG1PointInHex[0..32]);
    println!("Uncompressed Message X In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&msgG1PointInHex[32..64]);
    println!("Uncompressed Message Y In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);

    // Sign message
    let sig = Bn256.sign(&secret_key, &messageHexDec).unwrap();

    println!("\nCompressed Signature In\n {:?}\n\n", &sig);
    encoded = hex::encode(&sig);
    println!("\nCompressed Signature In Hex of Length {} \n {:?}\n\n", encoded.len(), &encoded);

    let uncompressedSig = G1::from_compressed(&sig).unwrap();
    println!("\nUncompressed Signature In Coords\n {:?}\n\n", &uncompressedSig);
    let uncompressedSigInHex = Bn256.to_uncompressed_g1(uncompressedSig).unwrap();
    println!("\nUncompressed Signature with {} elements\n {:?}\n\n", uncompressedSigInHex.len(), &uncompressedSigInHex);
    encoded = hex::encode(&uncompressedSigInHex[0..32]);
    println!("Uncompressed Signature X In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&uncompressedSigInHex[32..64]);
    println!("Uncompressed Signature Y In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);

    Bn256.verify(&sig, &messageHexDec, &public_key).unwrap();
    println!("Successful verification");

    let neg_g2 = -bn::G2::one();
    let public_key_neg_g2 = PublicKey(neg_g2).to_uncompressed().unwrap();
    println!("Uncompressed Public Key with {} elements\n {:?}\n\n", public_key_neg_g2.len(), &public_key_neg_g2);
    let mut encoded = hex::encode(&public_key_neg_g2[0..32]);
    println!("Uncompressed Public Key X Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&public_key_neg_g2[32..64]);
    println!("Uncompressed Public Key X Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&public_key_neg_g2[64..96]);
    println!("Uncompressed Public Key Y Real In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
    encoded = hex::encode(&public_key_neg_g2[96..128]);
    println!("Uncompressed Public Key Y Im In Hex of Length {} \n {:02X?}\n\n", encoded.len(), &encoded);
}
