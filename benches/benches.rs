// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod crypto;

use criterion::{criterion_group, criterion_main};

use crypto::*;

criterion_group!(
    merkle,
    merkle_root,
    merkle_prove_1million,
    merkle_verify_1million
);
criterion_main!(merkle);
