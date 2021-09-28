// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use algorsand::config;
use algorsand::data::{account, basics};
use algorsand::protocol;

pub fn old_keys_deletion(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut addr_bytes = [0; 32];
    rng.fill_bytes(&mut addr_bytes);
    let addr = basics::Address(addr_bytes);

    let params = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
    let key_dilution = params.default_key_dilution;
    let mut part = account::Participation::fill_db_with_participation_keys(
        addr,
        basics::Round(0),
        basics::Round(3_000_000),
        key_dilution,
    )
    .unwrap();
    let mut i = 0;

    c.bench_function("account::Participation::delete_old_keys()", |b| {
        b.iter_with_setup(
            || {
                i += 1;
                i
            },
            |i| part.delete_old_keys(basics::Round(i), params).unwrap(),
        );
    });
}
