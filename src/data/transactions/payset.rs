// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use super::*;
use crate::crypto::hashable::*;
use crate::protocol;

/// Represents a common, unforgeable, consistent, ordered set of SignedTxn objects.
//msgp:allocbound Payset 100000
struct Payset(Vec<SignedTxInBlock>);

impl Payset {
    /*
    /// Returns a commitment to the Payset, as a flat array.
    pub fn commit_flat(&self) -> CryptoHash {
        self.commit(false)
    }

    /// Like Commit, but with special handling for zero-length but non-nil paysets.
    pub fn commit_genesis() -> CryptoHash {
        self.commit(true)
    }

    /// Handles the logic for both Commit and CommitGenesis.
    fn commit(&self, genesis: bool) -> CryptoHash {
        // We used to build up Paysets from a nil slice with `append` during
        // block evaluation, meaning zero-length paysets would remain nil.
        // After we started allocating them up front, we started calling Commit
        // on zero-length but non-nil Paysets. However, we want payset
        // encodings to remain the same with or without this optimization.
        //
        // Additionally, the genesis block commits to a zero-length but non-nil
        // payset (the only block to do so), so we have to let the nil value
        // pass through.
        if !genesis && payset.len() == 0 {
            payset = nil
        }

        return hash_obj(self);
    }
    */
}

impl Hashable for Payset {
    // ToBeHashed implements the crypto.Hashable interface
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        //(protocol::PAYSET_FLAT, protocol::encode(payset))
        (protocol::PAYSET_FLAT, Vec::new())
    }
}
