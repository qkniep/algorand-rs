// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use rand::{thread_rng, RngCore};

use super::*;
use crate::config;
use crate::crypto::{self, hashable::*};
use crate::data::basics;
use crate::protocol;

#[test]
fn estimate_encoded_size() {
    let addr =
        basics::Address::from_str("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
            .unwrap();

    let mut rng = thread_rng();
    let mut buf = [0; 10];
    rng.fill_bytes(&mut buf);

    let proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
    let tx = Transaction::Payment(
        Header {
            sender: addr.clone(),
            fee: basics::MicroAlgos(100),
            first_valid: basics::Round(1000),
            last_valid: basics::Round(1000 + proto.max_tx_life),
            note: buf.to_vec(),
            genesis_id: "".to_owned(),
            genesis_hash: CryptoHash([0; 32]),
            group: CryptoHash([0; 32]),
            lease: [0; 32],
            rekey_to: basics::Address([0; 32]),
        },
        PaymentFields {
            receiver: addr,
            amount: basics::MicroAlgos(100),
            close_remainder_to: None,
        },
    );

    assert_eq!(tx.estimate_encoded_size(), 200);
}

#[test]
fn go_online_go_nonparticipating_contradiction() {
    // addr has no significance here other than being a normal valid address
    let addr =
        basics::Address::from_str("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
            .unwrap();

    let mut tx = generate_dummy_go_nonparticpating_tx(addr);
    // Generate keys, they don't need to be good or secure, just present.
    let v = crypto::OTSSecrets::generate(1, 1);
    // Also generate a new VRF key.
    let mut rng = thread_rng();
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let vrf = crypto::VrfKeypair::from_seed(seed);
    tx = Transaction::Keyreg(
        tx.header().clone(),
        KeyregFields {
            vote_pk: v.verifier,
            selection_pk: vrf.public(),
            vote_first: Default::default(),
            vote_last: Default::default(),
            vote_key_dilution: 0,
            nonparticipation: true,
        },
    );
    // This tx tries to both register keys to go online, and mark an account as non-participating.
    // It is not well-formed.
    let fee_sink = basics::Address([
        0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6,
        0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e,
        0xa2, 0x21,
    ]);
    assert!(tx
        .is_well_formed(
            &SpecialAddresses {
                fee_sink,
                rewards_pool: Default::default()
            },
            &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION]
        )
        .is_err());
}

#[test]
fn go_nonparticipating_well_formed() {
    // addr has no significance here other than being a normal valid address
    let addr =
        basics::Address::from_str("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
            .unwrap();

    let tx = generate_dummy_go_nonparticpating_tx(addr);
    let mut cur_proto = config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION].clone();

    if !cur_proto.support_become_non_participating_transactions {
        //t.Skipf("Skipping rest of test because current protocol version %v does not support become-nonparticipating transactions", protocol.ConsensusCurrentVersion)
        return;
    }

    // This tx is well-formed...
    let fee_sink = basics::Address([
        0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6,
        0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e,
        0xa2, 0x21,
    ]);
    assert!(tx
        .is_well_formed(
            &SpecialAddresses {
                fee_sink: fee_sink.clone(),
                rewards_pool: Default::default()
            },
            &cur_proto
        )
        .is_ok());
    // ...but it should stop being well-formed if the protocol does not support it
    cur_proto.support_become_non_participating_transactions = false;
    assert!(tx
        .is_well_formed(
            &SpecialAddresses {
                fee_sink,
                rewards_pool: Default::default()
            },
            &cur_proto
        )
        .is_err());
}

struct TestCase<'a> {
    tx: Transaction,
    spec: &'a SpecialAddresses,
    proto: &'a config::ConsensusParams,
    expected_error: Option<InvalidTx>,
}

#[test]
fn app_call_create_well_formed() {
    let fee_sink = basics::Address([
        0x7, 0xda, 0xcb, 0x4b, 0x6d, 0x9e, 0xd1, 0x41, 0xb1, 0x75, 0x76, 0xbd, 0x45, 0x9a, 0xe6,
        0x42, 0x1d, 0x48, 0x6d, 0xa3, 0xd4, 0xef, 0x22, 0x47, 0xc4, 0x9, 0xa3, 0x96, 0xb8, 0x2e,
        0xa2, 0x21,
    ]);
    let special_addr = &SpecialAddresses {
        fee_sink,
        rewards_pool: Default::default(),
    };
    let cur_proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
    let future_proto = &config::CONSENSUS.0[&protocol::ConsensusVersion::Future];
    let addr1 =
        basics::Address::from_str("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA")
            .unwrap();
    let usecases = vec![
        TestCase {
            tx: Transaction::AppCall(
                Header {
                    sender: addr1.clone(),
                    fee: basics::MicroAlgos(1000),
                    first_valid: basics::Round(100),
                    last_valid: basics::Round(105),
                    ..Default::default()
                },
                AppCallFields {
                    application_id: basics::AppIndex(0),
                    application_args: vec![b"write".to_vec()],
                    ..Default::default()
                },
            ),
            spec: special_addr,
            proto: cur_proto,
            expected_error: None,
        },
        TestCase {
            tx: Transaction::AppCall(
                Header {
                    sender: addr1.clone(),
                    fee: basics::MicroAlgos(1000),
                    first_valid: basics::Round(100),
                    last_valid: basics::Round(105),
                    ..Default::default()
                },
                AppCallFields {
                    application_id: basics::AppIndex(0),
                    application_args: vec![b"write".to_vec()],
                    ..Default::default()
                },
            ),
            spec: special_addr,
            proto: cur_proto,
            expected_error: None,
        },
        TestCase {
            tx: Transaction::AppCall(
                Header {
                    sender: addr1.clone(),
                    fee: basics::MicroAlgos(1000),
                    first_valid: basics::Round(100),
                    last_valid: basics::Round(105),
                    ..Default::default()
                },
                AppCallFields {
                    application_id: basics::AppIndex(0),
                    application_args: vec![b"write".to_vec()],
                    extra_program_pages: 3,
                    ..Default::default()
                },
            ),
            spec: special_addr,
            proto: future_proto,
            expected_error: None,
        },
        TestCase {
            tx: Transaction::AppCall(
                Header {
                    sender: addr1.clone(),
                    fee: basics::MicroAlgos(1000),
                    first_valid: basics::Round(100),
                    last_valid: basics::Round(105),
                    ..Default::default()
                },
                AppCallFields {
                    application_id: basics::AppIndex(0),
                    application_args: vec![b"write".to_vec()],
                    ..Default::default()
                },
            ),
            spec: special_addr,
            proto: future_proto,
            expected_error: None,
        },
    ];

    for usecase in &usecases {
        assert!(usecase
            .tx
            .is_well_formed(&usecase.spec, &usecase.proto)
            .is_ok());
    }
}

fn generate_dummy_go_nonparticpating_tx(addr: basics::Address) -> Transaction {
    let mut rng = thread_rng();
    let mut buf = [0; 10];
    rng.fill_bytes(&mut buf);

    let proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
    return Transaction::Keyreg(
        Header {
            sender: addr,
            fee: basics::MicroAlgos(proto.min_tx_fee),
            first_valid: basics::Round(1),
            last_valid: basics::Round(300),
            note: buf.to_vec(),
            genesis_id: "".to_owned(),
            genesis_hash: CryptoHash([0; 32]),
            group: CryptoHash([0; 32]),
            lease: [0; 32],
            rekey_to: basics::Address([0; 32]),
        },
        KeyregFields {
            nonparticipation: true,
            vote_first: basics::Round(0),
            vote_last: basics::Round(0),
            vote_key_dilution: 0,
            vote_pk: Default::default(),
            selection_pk: Default::default(),
        },
    );
}
