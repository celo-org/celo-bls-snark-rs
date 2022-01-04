use ark_std::rand::Rng;
use criterion::{criterion_group, criterion_main, Criterion};

use ark_bls12_377::{G1Projective, G2Projective};
use ark_ff::Zero;

use bls_crypto::{
    bls::Batch, hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22, PrivateKey,
    PublicKey, Signature, SIG_DOMAIN,
};

fn batch_bls_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls");
    group.sample_size(10);
    // Generate aggregate signatures on 100-validators across 1000 blocks
    const NUM_BLOCKS: usize = 300;
    const NUM_VALIDATORS: usize = 20;
    let rng = &mut ark_std::test_rng();
    let try_and_increment = &*COMPOSITE_HASH_TO_G1_CIP22;

    // generate some msgs and extra data
    let mut msgs = Vec::new();
    for _ in 0..NUM_BLOCKS {
        let message: Vec<u8> = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let extra_data: Vec<u8> = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        msgs.push((message, extra_data));
    }

    let msgs = msgs
        .iter()
        .map(|(m, d)| (m.as_ref(), d.as_ref()))
        .collect::<Vec<_>>();

    // get each signed by a committee _on the same domain_ and get the agg sigs of the commitee
    let mut asig = G1Projective::zero();
    let mut aggregate_pubkeys = Vec::new();
    let mut aggregate_sigs = Vec::new();
    let mut epoch_batches = Vec::new();

    for msg in msgs.iter().take(NUM_BLOCKS) {
        let mut epoch_pubkey = G2Projective::zero();
        let mut epoch_sig = G1Projective::zero();
        let mut epoch_batch = Batch::new(msg.0, msg.1);
        for _ in 0..NUM_VALIDATORS {
            let sk = PrivateKey::generate(rng);
            let s = sk.sign(msg.0, msg.1, try_and_increment).unwrap();

            epoch_sig += s.as_ref();
            epoch_pubkey += sk.to_public().as_ref();
            epoch_batch.add(sk.to_public(), s);
        }

        aggregate_pubkeys.push(PublicKey::from(epoch_pubkey));
        aggregate_sigs.push(Signature::from(epoch_sig));

        asig += epoch_sig;

        epoch_batches.push(epoch_batch);
    }

    // verify the sigs individually in a loop
    group.bench_function("per-epoch aggregate screening", |b| {
        b.iter(|| {
            aggregate_pubkeys
                .iter()
                .zip(&aggregate_sigs)
                .zip(&msgs)
                .for_each(|((pk, sig), msg)| {
                    pk.verify(msg.0, msg.1, sig, try_and_increment).unwrap()
                })
        })
    });

    let asig = Signature::from(asig);
    group.bench_function("all epoch aggregate screening", |b| {
        b.iter(|| {
            asig.batch_verify(&aggregate_pubkeys, SIG_DOMAIN, &msgs, try_and_increment)
                .unwrap()
        })
    });

    group.bench_function("per-epoch batch verification", |b| {
        b.iter(|| {
            epoch_batches
                .iter()
                .for_each(|batch| batch.verify(try_and_increment).unwrap())
        })
    });

    group.bench_function("per-epoch individual verification", |b| {
        b.iter(|| {
            epoch_batches
                .iter()
                .for_each(|batch| batch.verify_each(try_and_increment).unwrap())
        })
    });
}

criterion_group!(benches, batch_bls_comparison);
criterion_main!(benches);
