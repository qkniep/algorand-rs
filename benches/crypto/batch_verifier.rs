// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::Criterion;
use ed25519_dalek::{Keypair, Signer};
use rand::{distributions::Alphanumeric, rngs::OsRng, thread_rng, Rng};

use algorsand::crypto::batch_verifier::*;

pub fn batch_verifier(c: &mut Criterion) {
    let kp = Keypair::generate(&mut OsRng {});

    c.bench_function("batch_verifier::enque_sig", |b| {
        let mut bv = BatchVerifier::with_capacity(1);
        b.iter_with_setup(
            || random_string(),
            |s| bv.enque_sig(kp.public, &s, kp.sign(&s)),
        );
        assert!(bv.verify().is_ok());
    });
}

fn random_string() -> Vec<u8> {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(|c| c as u8)
        .collect()
}
