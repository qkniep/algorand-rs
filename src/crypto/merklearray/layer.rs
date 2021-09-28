// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use rayon::prelude::*;

use crate::crypto::*;
use crate::protocol;

/// A layer of the Merkle tree consists of a dense array of hashes at that level of the tree.
/// Hashes beyond the end of the array (e.g., if the number of leaves is not an exact power of 2) are implicitly zero.
#[derive(Clone, Debug)]
pub struct Layer(pub Vec<CryptoHash>);

/// A pair represents an internal node in the Merkle tree.
pub struct Pair {
    pub l: CryptoHash,
    pub r: CryptoHash,
}

impl Layer {
    /// Takes a Layer representing some level in the tree, and calculates the next-higher level in the tree,
    /// represented as a Layer.
    pub fn up(&self) -> Self {
        let v = self
            .0
            .par_chunks(2)
            .map(|c| {
                hash_obj(&Pair {
                    l: c[0].clone(),
                    r: c.get(1).unwrap_or(&Default::default()).clone(),
                })
            })
            .collect();

        Layer(v)
    }
}

impl Hashable for Pair {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        let mut buf = [0; 2 * HASH_LEN];
        buf[..HASH_LEN].copy_from_slice(&self.l.0[..]);
        buf[HASH_LEN..].copy_from_slice(&self.r.0[..]);
        (protocol::MERKLE_ARRAY_NODE, buf.to_vec())
    }
}
