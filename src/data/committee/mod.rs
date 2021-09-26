// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use crate::data::basics;

/// A Selector deterministically defines a cryptographic sortition committee. It
/// contains both the input to the sortition VRF and the size of the sortition
/// committee.
type Selector interface {
	// The hash of a struct which implements Selector is used as the input to the VRF.
	crypto::Hashable

	// CommitteeSize returns the size of the committee determined by this Selector.
	CommitteeSize(config.ConsensusParams) uint64
}

/// Pairs an account's address with its associated data.
///
/// This struct is used to decouple LedgerReader.AccountData from basics.BalanceRecord.
//msgp:ignore BalanceRecord
pub struct BalanceRecord {
	basics::AccountData,
	pub addr: basics::Address,
}

/// Encodes the parameters used to verify membership in a committee.
struct Membership {
	pub record:     BalanceRecord,
	pub selector:  Selector,
	pub total_money: basics::MicroAlgos,
}

/// Contains cryptographic entropy which can be used to determine a committee.
pub struct Seed([32]byte);

impl Hashable for Seed {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::SEED, self.0[..].to_vec())
    }
}
