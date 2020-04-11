use bls_crypto::{hash_to_curve::try_and_increment::DIRECT_HASH_TO_G1, PrivateKey};

use algebra::bytes::{FromBytes, ToBytes};

use clap::{App, Arg};

fn main() {
    let matches = App::new("BLS Proof of Possession")
        .about("Generates a proof of posession for the given private key")
        .arg(
            Arg::with_name("key")
                .short("k")
                .value_name("KEY")
                .help("Sets the BLS private key")
                .required(true),
        )
        .get_matches();

    let key = matches.value_of("key").unwrap();

    let key_bytes = hex::decode(key).unwrap();

    let try_and_increment = &*DIRECT_HASH_TO_G1;
    let sk = PrivateKey::read(key_bytes.as_slice()).unwrap();
    let pk = sk.to_public();
    let mut pk_bytes = vec![];
    pk.write(&mut pk_bytes).unwrap();
    let pop = sk.sign_pop(&pk_bytes, try_and_increment).unwrap();
    let mut pop_bytes = vec![];
    pop.write(&mut pop_bytes).unwrap();

    pk.verify_pop(&pk_bytes, &pop, try_and_increment).unwrap();

    let pop_hex = hex::encode(&pop_bytes);
    println!("{}", pop_hex);
}
