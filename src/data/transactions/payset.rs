// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use super::*;
use crate::crypto::hashable::*;
use crate::protocol;

/// Represents a common, unforgeable, consistent, ordered set of SignedTxn objects.
//msgp:allocbound Payset 100000
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Payset(pub Vec<SignedTxInBlock>);

// TODO there was some weird differentiation between nil and zero-length paysets in go-algorand

impl Payset {
    /// Returns a commitment to the Payset, as a flat array.
    pub fn commit_flat(&self) -> CryptoHash {
        self.commit(false)
    }

    pub fn commit_genesis(&self) -> CryptoHash {
        self.commit(true)
    }

    /// Handles the logic for both Commit and CommitGenesis.
    fn commit(&self, genesis: bool) -> CryptoHash {
        hash_obj(self)
    }
}

impl Hashable for Payset {
    // ToBeHashed implements the crypto.Hashable interface
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::PAYSET_FLAT, protocol::encode(&self))
    }
}
