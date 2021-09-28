// Copyright (C) 2021 Quentin M. Knipe <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::VecDeque;

use super::*;
use crate::crypto::hashable::*;

/// Represents the siblings needed to compute the root hash given a set of leaf nodes.
/// This data structure can operate in two modes:
///   - build up the set of sibling hints, if tree is not empty, or
///   - use the set of sibling hints, if tree is empty
#[derive(Debug)]
pub struct Siblings<'a> {
    pub tree: &'a Tree,
    pub hints: VecDeque<CryptoHash>,
}

/// Represents a subset of a layer (i.e., nodes at some level in the Merkle tree).
#[derive(Debug)]
pub struct PartialLayer(pub Vec<LayerItem>);

/// Represents one element in the partial layer.
#[derive(Clone, Debug)]
pub struct LayerItem {
    pub pos: u64,
    pub hash: CryptoHash,
}

impl Siblings<'_> {
    /// Returns the sibling from tree level l (0 being the leaves) position i.
    fn get(&mut self, l: u64, i: u64) -> Result<CryptoHash, ()> {
        if self.tree.levels.is_empty() {
            if !self.hints.is_empty() {
                return Ok(self.hints.pop_front().unwrap());
            }

            //err = fmt.Errorf("no more sibling hints")
            return Err(());
        }

        if l >= self.tree.levels.len() as u64 {
            //err = fmt.Errorf("level %d beyond tree height %d", l, len(s.tree.levels))
            return Err(());
        }

        let res = self.tree.levels[l as usize]
            .0
            .get(i as usize)
            .unwrap_or(&CryptoHash([0; HASH_LEN]));

        self.hints.push_back(res.clone());
        Ok(res.clone())
    }
}

impl PartialLayer {
    /// Takes a partial layer at level l, and returns the next-higher (partial) level in the tree.
    /// Since the layer is partial, up() requires siblings.
    ///
    /// The implementation is deterministic to ensure that up() asks for siblings
    /// in the same order both when generating a proof, as well as when checking the proof.
    ///
    /// If `do_hash` is false, fill in zero hashes, which suffices for constructing a proof.
    pub fn up(&self, s: &mut Siblings, l: u64, do_hash: bool) -> Result<PartialLayer, ()> {
        let mut res = PartialLayer(Vec::new());

        let mut it = self.0.iter().enumerate();
        while let Some((i, LayerItem { pos, hash })) = it.next() {
            let sibling_pos = pos ^ 1;
            let sibling_hash: CryptoHash;

            if i + 1 < self.0.len() && self.0[i + 1].pos == sibling_pos {
                // If our sibling is also in the partial layer, use its hash (and skip over its position).
                sibling_hash = self.0[i + 1].hash.clone();
                it.next();
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
                        r: sibling_hash,
                    }
                } else {
                    // We are right
                    Pair {
                        l: sibling_hash,
                        r: hash.clone(),
                    }
                };
                next_layer_hash = hash_obj(&p);
            }

            res.0.push(LayerItem {
                pos: next_layer_pos,
                hash: next_layer_hash,
            });
        }

        Ok(res)
    }
}
