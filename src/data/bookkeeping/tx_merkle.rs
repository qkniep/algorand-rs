// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use super::Block;
use crate::{
    crypto::{self, hashable::Hashable},
    data::transactions,
    protocol,
};

/// Representation of the transactions in this block,
/// along with their `ApplyData`, as an array for the merklearray package.
pub struct TxMerkleArray(pub Vec<TxMerkleElem>);

/// Represents a leaf in the Merkle tree of all transactions in a block.
pub struct TxMerkleElem {
    pub tx: transactions::Transaction,
    pub stib: transactions::SignedTxInBlock,
}

impl TxMerkleArray {
    /// Get implements the merklearray.Array interface.
    pub fn from_block(block: &Block) -> Result<Self, ()> {
        let mut res = Vec::with_capacity(block.payset.0.len());

        for stib in &block.payset.0 {
            let stad = block.header.decode_signed_tx(stib)?;
            res.push(TxMerkleElem {
                stib: stib.clone(),
                tx: stad.tx.tx,
            });
        }

        Ok(Self(res))
    }
}

impl Hashable for TxMerkleElem {
    /// ToBeHashed implements the crypto.Hashable interface.
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        // The leaf contains two hashes: the transaction ID (hash of the
        // transaction itself), and the hash of the entire `SignedTxInBlock`.
        let txid = self.tx.id();
        let stib = crypto::hash_obj(&self.stib);

        let mut buf = [0; 2 * crypto::HASH_LEN];
        buf[..crypto::HASH_LEN].copy_from_slice(&txid.0 .0);
        buf[crypto::HASH_LEN..].copy_from_slice(&stib.0);

        (protocol::TX_MERKLE_LEAF, buf.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
