// Copyright (C) 2021 Quentin M. Knipe <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryInto;

use super::*;
use crate::crypto::hashable::*;

/// Represents the siblings needed to compute the root hash given a set of leaf nodes.
/// This data structure can operate in two modes:
///   - build up the set of sibling hints, if tree is not empty, or
///   - use the set of sibling hints, if tree is empty
pub struct Siblings {
    pub tree: Tree,
    pub hints: Vec<CryptoHash>,
}

/// Represents a subset of a layer (i.e., nodes at some level in the Merkle tree).
pub struct PartialLayer(pub Vec<LayerItem>);

/// Represents one element in the partial layer.
#[derive(Clone, PartialEq, Eq)]
pub struct LayerItem {
    pub pos: u64,
    pub hash: CryptoHash,
}

impl Siblings {
    /// Returns the sibling from tree level l (0 being the leaves) position i.
    fn get(&mut self, l: u64, i: u64) -> Result<CryptoHash, ()> {
        let mut res = CryptoHash([0; HASH_LEN]);

        if self.tree.levels.is_empty() {
            if self.hints.is_empty() {
                let res = self.hints[0].clone();
                self.hints.drain(..1);
                return Ok(res);
            }

            //err = fmt.Errorf("no more sibling hints")
            return Err(());
        }

        if l >= self.tree.levels.len() as u64 {
            //err = fmt.Errorf("level %d beyond tree height %d", l, len(s.tree.levels))
            return Err(());
        }

        if i < self.tree.levels[l as usize].0.len() as u64 {
            res = self.tree.levels[l as usize].0[i as usize].clone();
        }

        self.hints.push(res.clone());
        return Ok(res);
    }
}

impl PartialLayer {
    /// Takes a partial layer at level l, and returns the next-higher (partial) level in the tree.
    /// Since the layer is partial, up() requires siblings.
    ///
    /// The implementation is deterministic to ensure that up() asks for siblings
    /// in the same order both when generating a proof, as well as when checking the proof.
    ///
    /// If doHash is false, fill in zero hashes, which suffices for constructing a proof.
    pub fn up(&self, s: &mut Siblings, l: u64, do_hash: bool) -> Result<PartialLayer, ()> {
        let mut res = PartialLayer(Vec::new());

        for (mut i, LayerItem { pos, hash }) in self.0.iter().enumerate() {
            let sibling_pos = pos ^ 1;
            let mut sibling_hash = CryptoHash([0; HASH_LEN]);

            if i + 1 < self.0.len() && self.0[i + 1].pos == sibling_pos {
                // If our sibling is also in the partial layer, use its hash (and skip over its position).
                sibling_hash = self.0[i + 1].hash.clone();
                i += 1;
            } else {
                // Ask for the sibling hash from the tree / proof.
                sibling_hash = s.get(l, sibling_pos)?;
            }

            let next_layer_pos = pos / 2;
            let mut next_layer_hash = CryptoHash([0; HASH_LEN]);

            if do_hash {
                let p = if pos & 1 == 0 {
                    // We are left
                    Pair {
                        l: hash.clone(),
                        r: sibling_hash.clone(),
                    }
                } else {
                    // We are right
                    Pair {
                        l: sibling_hash,
                        r: hash.clone(),
                    }
                };
                next_layer_hash = CryptoHash(p.hash_rep().as_slice().try_into().unwrap());
            }

            res.0.push(LayerItem {
                pos: next_layer_pos,
                hash: next_layer_hash,
            });
        }

        return Ok(res);
    }
}

impl std::cmp::PartialOrd for LayerItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.pos.partial_cmp(&other.pos)
    }
}

impl std::cmp::Ord for LayerItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pos.cmp(&other.pos)
    }
}
