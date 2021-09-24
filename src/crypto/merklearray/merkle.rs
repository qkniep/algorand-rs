// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::convert::TryInto;

use super::partial::*;
use super::*;
use crate::crypto::hashable::*;

/// Tree is a Merkle tree, represented by layers of nodes (hashes) in the tree at each height.
#[derive(Clone)]
pub struct Tree {
    // Level 0 is the leaves.
    pub levels: Vec<Layer>,
}

impl Tree {
    /// Constructs a Merkle tree given an array.
    pub fn from_array(array: Vec<impl Hashable>) -> Result<Self, ()> {
        let mut tree = Self {
            levels: vec![Layer(
                array
                    .iter()
                    .map(|h| CryptoHash(h.hash_rep().as_slice().try_into().unwrap()))
                    .collect(),
            )],
        };

        if array.len() > 0 {
            while tree.top_layer().0.len() > 1 {
                tree.levels.push(tree.top_layer().up());
            }
        }

        return Ok(tree);
    }

    /// Returns the root hash of the tree.
    pub fn root(&self) -> CryptoHash {
        // Special case: commitment to zero-length array
        if self.levels.is_empty() {
            return CryptoHash([0; HASH_LEN]);
        }

        return self.top_layer().0[0].clone();
    }

    /// Constructs a proof for some set of positions in the array that was used to construct the tree.
    pub fn prove(&self, idxs: &mut Vec<u64>) -> Result<Vec<CryptoHash>, ()> {
        const VALIDATE_PROOF: bool = false;

        if idxs.is_empty() {
            return Err(());
        }

        // Special case: commitment to zero-length array
        if self.levels.is_empty() {
            return Err(());
            //return nil, fmt.Errorf("proving in zero-length commitment")
        }

        idxs.sort();

        let mut pl = PartialLayer(Vec::new());
        for &pos in idxs.iter() {
            if pos >= self.levels[0].0.len() as u64 {
                //return nil, fmt.Errorf("pos %d larger than leaf count %d", pos, len(tree.levels[0]))
                return Err(());
            }

            // Discard duplicates
            if pl.0.len() > 0 && pl.0[pl.0.len() - 1].pos == pos {
                continue;
            }

            pl.0.push(LayerItem {
                pos,
                hash: self.levels[0].0[pos as usize].clone(),
            });
        }

        let mut s = Siblings {
            tree: self.clone(),
            hints: Vec::new(),
        };

        for l in 0..self.levels.len() - 1 {
            pl = pl.up(&mut s, l as u64, VALIDATE_PROOF)?;
        }

        // Confirm that we got the same root hash
        if pl.0.len() != 1 {
            //return nil, fmt.Errorf("internal error: partial layer produced %d hashes", len(pl))
            return Err(());
        }

        if VALIDATE_PROOF {
            let root_calculated = pl.0[0].clone();
            if root_calculated.pos != 0 || root_calculated.hash != self.top_layer().0[0] {
                //return nil, fmt.Errorf("internal error: root mismatch during proof")
                return Err(());
            }
        }

        return Ok(s.hints);
    }

    /// Ensures that the positions in elems correspond to the respective hashes in a tree with the given root hash.
    /// The proof is expected to be the proof returned by `prove()`.
    pub fn verify(
        root: CryptoHash,
        elems: HashMap<u64, CryptoHash>,
        proof: Vec<CryptoHash>,
    ) -> Result<(), ()> {
        if elems.is_empty() {
            if !proof.is_empty() {
                //return fmt.Errorf("non-empty proof for empty set of elements")
                return Err(());
            }

            return Ok(());
        }

        let mut pl = PartialLayer(Vec::new());
        for (pos, elem) in elems {
            pl.0.push(LayerItem { pos, hash: elem });
        }

        //sort.Slice(pl, func(i, j int) bool { return pl[i].pos < pl[j].pos })
        pl.0.sort();

        let mut s = Siblings {
            tree: Tree { levels: Vec::new() },
            hints: proof,
        };

        for l in 0..s.hints.len() {
            pl = pl.up(&mut s, l as u64, true)?;

            if l > 64 {
                //return fmt.Errorf("Verify exceeded 64 levels, more than 2^64 leaves not supported")
                return Err(());
            }
        }

        let root_calculated = pl.0[0].clone();
        if root_calculated.pos != 0 || root_calculated.hash != root {
            //return fmt.Errorf("root mismatch")
            return Err(());
        }

        return Ok(());
    }

    fn top_layer(&self) -> &Layer {
        &self.levels[self.levels.len() - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
