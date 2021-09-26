// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::*;
use crate::data::basics;

/// EvalDelta stores StateDeltas for an application's global key/value store, as
/// well as StateDeltas for some number of accounts holding local state for that
/// application
#[derive(Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalDelta {
    pub global_delta: basics::StateDelta,

    /// When decoding EvalDeltas, the integer key represents an offset into
    /// [txn.Sender, txn.Accounts[0], txn.Accounts[1], ...]
    pub local_deltas: HashMap<u64, basics::StateDelta>,

    pub logs: Vec<String>,

    /// Intentionally, temporarily wrong - need to decide how to
    /// allocbound properly when structure is recursive.
    /// Even a bound of 2 would allow arbitrarily large object if deep.
    pub inner_txs: Vec<SignedTxWithAD>,
}

/*
// Equal compares two EvalDeltas and returns whether or not they are
// equivalent. It does not care about nilness equality of LocalDeltas,
// because the msgpack codec will encode/decode an empty map as nil, and we want
// an empty generated EvalDelta to equal an empty one we decode off the wire.
func (ed EvalDelta) Equal(o EvalDelta) bool {
    // LocalDeltas length should be the same
    if len(ed.LocalDeltas) != len(o.LocalDeltas) {
        return false
    }

    // All keys and local StateDeltas should be the same
    for k, v := range ed.LocalDeltas {
        // Other LocalDelta must have value for key
        ov, ok := o.LocalDeltas[k]
        if !ok {
            return false
        }

        // Other LocalDelta must have same value for key
        if !ov.Equal(v) {
            return false
        }
    }

    // GlobalDeltas must be equal
    if !ed.GlobalDelta.Equal(o.GlobalDelta) {
        return false
    }

    // Logs must be equal
    if len(ed.Logs) != len(o.Logs) {
        return false
    }
    for i, l := range ed.Logs {
        if l != o.Logs[i] {
            return false
        }
    }

    // InnerTxns must be equal
    if len(ed.InnerTxns) != len(o.InnerTxns) {
        return false
    }
    for i, txn := range ed.InnerTxns {
        if !txn.SignedTxn.equal(o.InnerTxns[i].SignedTxn) {
            return false
        }
        if !txn.ApplyData.Equal(o.InnerTxns[i].ApplyData) {
            return false
        }
    }

    return true
}
*/

/*
// equal compares two SignedTransactions for equality.  It's not
// exported because it ought to be written as (many, very, very
// tedious) field comparisons. == is not defined on almost any of the
// subfields because of slices.
func (stx SignedTxn) equal(o SignedTxn) bool {
    stxenc := stx.MarshalMsg(protocol.GetEncodingBuf())
    defer protocol.PutEncodingBuf(stxenc)
    oenc := o.MarshalMsg(protocol.GetEncodingBuf())
    defer protocol.PutEncodingBuf(oenc)
    return bytes.Equal(stxenc, oenc)
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
