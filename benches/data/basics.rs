// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::str::FromStr;

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use algorsand::data::basics::Address;

pub fn address_to_string(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut addr_bytes = [0; 32];

    c.bench_function("basics::Address::to_string()", |b| {
        b.iter_with_setup(
            || {
                rng.fill_bytes(&mut addr_bytes);
                Address(addr_bytes)
            },
            |addr| addr.to_string(),
        );
    });
}

pub fn address_from_str(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut addr_bytes = [0; 32];

    c.bench_function("basics::Address::from_str()", |b| {
        b.iter_with_setup(
            || {
                rng.fill_bytes(&mut addr_bytes);
                let addr = Address(addr_bytes);
                addr.to_string()
            },
            |addr_str| Address::from_str(&addr_str),
        );
    });
}
