// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use super::transactions;
use crate::crypto;

/// Used as the in-memory representation of a signed transaction group.
/// Unlike the plain array of signed transactions, this includes transaction origination and counter
/// used by the transaction pool and the transaction sync.
struct SignedTxGroup {
    /// Signed transactions that are included in this transaction group.
    transactions: SignedTxVec,
    /// Whether the trancation group was inroduced via the REST API or by the transaction sync.
    locally_originated: bool,
    /// Monotonic increasing counter, that provides an identify for each transaction group.
    /// The transaction sync is using it as a way to scan the transactions group list more efficiently,
    /// as it can continue scanning the list from the place where it last stopped.
    /// This is local, assigned when the group is first seen by the local transaction pool.
    group_counter: u64,
    /// Hash of the entire transaction group.
    group_tx_id: transactions::TxID,
    /// Length, in bytes, of the msgpack encoding of all the TXs in this transaction group.
    encoded_length: u32,
}

/// Vec of `SignedTx`s, allowing us to easily define the id() function.
struct SignedTxVec(Vec<transactions::SignedTx>);

impl SignedTxVec {
    /// ID calculate the hash of the signed transaction group.
    fn id(&self) -> transactions::TxID {
        // TODO let enc = [protocol::TX_GROUP, self.encode()].concat();
        let enc = [0; 16];
        return transactions::TxID(crypto::hash(&enc));
    }
}

/// Represents an invalid GroupCounter value.
/// It's being used to indicate the absence of an entry within a Vec<SignedTxGroup> with a particular GroupCounter value.
const INVALID_SIGNED_TX_GROUP_COUNTER: u64 = u64::MAX;
