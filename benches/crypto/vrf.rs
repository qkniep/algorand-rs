// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::{BatchSize, Criterion};
use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

use algorsand::crypto::vrf::*;

pub fn vrf_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut seed = [0; 32];

    c.bench_function("vrf_verify", |b| {
        b.iter_batched(
            || {
                rng.fill_bytes(&mut seed);
                let kp = VrfKeypair::from_seed(seed);

                let r_str: String = rng.sample_iter(&Alphanumeric).take(100).collect();
                let proof = kp.prove_bytes(r_str.as_bytes()).unwrap();
                (kp.public(), r_str, proof)
            },
            |(pk, msg, proof)| pk.verify_bytes(&proof, msg.as_bytes()).unwrap(),
            BatchSize::SmallInput,
        );
    });
}
