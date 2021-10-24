// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use algorsand::crypto;
use algorsand::data::committee::sortition;

pub fn sortition_select(c: &mut Criterion) {
    let mut rng = thread_rng();

    c.bench_function("committee::sortition::select()", |b| {
        b.iter_with_setup(
            || {
                let mut key = crypto::CryptoHash([0; crypto::HASH_LEN]);
                rng.fill_bytes(&mut key.0);
                key
            },
            |key| sortition::select(1_000_000, 1_000_000_000_000, 2500.0, &key),
        );
    });
}
