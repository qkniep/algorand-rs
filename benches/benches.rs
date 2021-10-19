// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod crypto;
mod data;

use criterion::{criterion_group, criterion_main};

use crypto::*;
use data::*;

criterion_group!(batch, batch_verifier);
criterion_group!(merkle, merkle_root, merkle_prove, merkle_verify);
criterion_group!(vrf, vrf_verify);

criterion_group!(account, old_keys_deletion);
criterion_group!(basics, address_from_str, address_to_string);

criterion_main!(batch, merkle, vrf, account, basics);
