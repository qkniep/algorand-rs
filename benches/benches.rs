// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod crypto;

use criterion::{criterion_group, criterion_main};

use crypto::*;

criterion_group!(batch, batch_verifier);
criterion_group!(merkle, merkle_root, merkle_prove, merkle_verify);
criterion_group!(vrf, vrf_verify);

criterion_main!(batch, merkle, vrf);
