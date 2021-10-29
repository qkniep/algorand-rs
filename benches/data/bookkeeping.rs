// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use criterion::{BatchSize, Criterion};
use rand::{thread_rng, RngCore};

use algorsand::data::{basics, bookkeeping::Block, transactions};
use algorsand::{config, protocol};

pub fn tx_roots(c: &mut Criterion) {
    let mut rng = thread_rng();
    let mut blk = Block::default();
    blk.header.upgrade_state.current_protocol = protocol::CURRENT_CONSENSUS_VERSION;
    rng.fill_bytes(&mut blk.header.genesis_hash.0);

    let proto = &config::CONSENSUS.0[&blk.header.upgrade_state.current_protocol];

    for i in 0.. {
        let mut header = transactions::Header {
            genesis_hash: blk.header.genesis_hash.clone(),
            ..Default::default()
        };
        rng.fill_bytes(&mut header.sender.0);

        let mut fields = transactions::PaymentFields {
            amount: basics::MicroAlgos(rng.next_u64()),
            ..Default::default()
        };
        rng.fill_bytes(&mut fields.receiver.0);
        let tx = transactions::Transaction {
            header,
            fields: transactions::TxFields::Payment(fields),
        };

        let st = transactions::SignedTx {
            tx,
            sig: ed25519_dalek::Signature::new([0; ed25519_dalek::SIGNATURE_LENGTH]),
            msig: Default::default(),
            lsig: Default::default(),
            auth_addr: Default::default(),
        };
        let ad = transactions::ApplyData::default();

        let stib = blk.header.encode_signed_tx(st, ad).unwrap();

        blk.payset.0.push(stib);

        if (i % 1024 == 0)
            && protocol::encode(&blk.payset).len() >= proto.max_tx_bytes_per_block as usize
        {
            break;
        }
    }

    c.bench_function("bookkeeping::tx_roots FlatCommit", |b| {
        b.iter(|| blk.payset.commit_flat());
    });

    c.bench_function("bookkeeping::tx_roots MerkleCommit", |b| {
        b.iter(|| blk.tx_merkle_tree().unwrap().root());
    });
}
