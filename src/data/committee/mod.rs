// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

pub mod credential;
pub mod sortition;
#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};

use crate::config;
use crate::crypto::hashable::*;
use crate::data::basics;
use crate::protocol;

/// A Selector deterministically defines a cryptographic sortition committee.
/// It contains both the input to the sortition VRF and the size of the sortition committee.
pub trait Selector: Hashable {
    /// Returns the size of the committee determined by this `Selector`.
    fn committee_size(&self, params: &config::ConsensusParams) -> u64;
}

/// Pairs an account's address with its associated data.
///
/// This struct is used to decouple LedgerReader.AccountData from basics.BalanceRecord.
//msgp:ignore BalanceRecord
pub struct BalanceRecord {
    pub data: basics::AccountData,
    pub addr: basics::Address,
}

/// Encodes the parameters used to verify membership in a committee.
struct Membership<S: Selector> {
    pub record: BalanceRecord,
    pub selector: S,
    pub total_money: basics::MicroAlgos,
}

/// Contains cryptographic entropy which can be used to determine a committee.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Seed(pub [u8; 32]);

impl Hashable for Seed {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::SEED, self.0[..].to_vec())
    }
}
