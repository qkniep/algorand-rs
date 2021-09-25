// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;

use criterion::Criterion;
use rand::{thread_rng, RngCore};

use algorsand::crypto::hashable::*;
use algorsand::crypto::merklearray::*;

pub fn merkle_root(c: &mut Criterion) {
    const ELEMENTS: usize = 100_000;
    let a = (0..ELEMENTS)
        .into_iter()
        .map(|i| format!("test{}", i).to_owned())
        .collect();

    c.bench_function("merkle build+root (100k)", |b| {
        b.iter(|| {
            let tree = Tree::from_array(&a).unwrap();
            tree.root()
        })
    });
}

pub fn merkle_prove(c: &mut Criterion) {
    const ELEMENTS: usize = 1_000_000;
    let a = (0..ELEMENTS)
        .into_iter()
        .map(|i| format!("test{}", i).to_owned())
        .collect();
    let tree = Tree::from_array(&a).unwrap();

    c.bench_function("merkle prove (1M)", |b| {
        b.iter_with_setup(
            || thread_rng().next_u32() as usize % a.len(),
            |i| tree.prove(&mut vec![i as u64]).unwrap(),
        )
    });
}

pub fn merkle_verify(c: &mut Criterion) {
    const ELEMENTS: usize = 100_000;
    let a = (0..ELEMENTS)
        .into_iter()
        .map(|i| format!("test{}", i).to_owned())
        .collect();
    let tree = Tree::from_array(&a).unwrap();
    let root = tree.root();

    let proofs: Vec<Vec<CryptoHash>> = (0..a.len())
        .into_iter()
        .map(|i| tree.prove(&mut vec![i as u64]).unwrap())
        .collect();

    c.bench_function("merkle verify (100k)", |b| {
        b.iter_with_setup(
            || {
                let i = thread_rng().next_u32() as usize % a.len();
                let mut elems = HashMap::new();
                elems.insert(i as u64, hash_obj(&a[i].clone()));
                (i, elems)
            },
            |(i, elems)| {
                Tree::verify(&root, elems, &proofs[i]).unwrap();
            },
        )
    });
}
