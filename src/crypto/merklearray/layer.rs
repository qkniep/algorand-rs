// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

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
        let n = self.0.len();
        let mut res = Layer(Vec::with_capacity((n + 1) / 2));

        // TODO use some equivalent of Go workers
        for i in (0..n).step_by(2) {
            let mut p = Pair {
                l: self.0[i].clone(),
                r: Default::default(),
            };
            if i + 1 < n {
                p.r = self.0[i + 1].clone();
            }
            res.0.push(hash_obj(&p));
        }

        return res;
    }
}

// TODO optimized hash_obj ala go-algorand?
impl Hashable for Pair {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        let mut buf = [0; 2 * HASH_LEN];
        buf[..HASH_LEN].copy_from_slice(&self.l.0[..]);
        buf[HASH_LEN..].copy_from_slice(&self.r.0[..]);
        return (protocol::MERKLE_ARRAY_NODE, buf.to_vec());
    }
}
