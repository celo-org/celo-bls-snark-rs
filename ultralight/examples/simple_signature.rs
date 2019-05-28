#[macro_use]
extern crate algebra;

#[macro_use]
extern crate log;

use bls_zexe::{
    bls::keys::{PrivateKey, PublicKey, Signature},
    curve::hash::try_and_increment::TryAndIncrement,
    hash::composite::CompositeHasher,
};

use algebra::bytes::ToBytes;

use clap::{App, Arg};
use env_logger;
use rand::thread_rng;

fn main() {
    env_logger::init();

    let matches = App::new("SimpleAggregatedSignature")
        .about("Show an example of a simple signature with a random key")
        .arg(
            Arg::with_name("message")
                .short("m")
                .value_name("MESSAGE")
                .help("Sets the message to sign")
                .required(true),
        )
        .get_matches();

    let message = matches.value_of("message").unwrap();

    let rng = &mut thread_rng();

    let composite_hasher = CompositeHasher::new().unwrap();
    let try_and_increment = TryAndIncrement::new(&composite_hasher);
    let sk1 = PrivateKey::generate(rng);
    debug!("sk1: {}", hex::encode(to_bytes!(sk1.get_sk()).unwrap()));
    let sk2 = PrivateKey::generate(rng);
    debug!("sk2: {}", hex::encode(to_bytes!(sk2.get_sk()).unwrap()));

    let sig1 = sk1.sign(&message.as_bytes(), &try_and_increment).unwrap();
    debug!("sig1: {}", hex::encode(to_bytes!(sig1.get_sig()).unwrap()));
    let sig2 = sk2.sign(&message.as_bytes(), &try_and_increment).unwrap();
    debug!("sig2: {}", hex::encode(to_bytes!(sig2.get_sig()).unwrap()));

    let apk = PublicKey::aggregate(&[&sk1.to_public(), &sk2.to_public()]);
    debug!("apk: {}", hex::encode(to_bytes!(apk.get_pk()).unwrap()));
    let asig = Signature::aggregate(&[&sig1, &sig2]);
    debug!("asig: {}", hex::encode(to_bytes!(asig.get_sig()).unwrap()));
    apk.verify(&message.as_bytes(), &asig, &try_and_increment)
        .unwrap();
    debug!("aggregated signature verified successfully");
}
