// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::{HashMap, VecDeque};

use super::partial::*;
use super::*;
use crate::crypto::hashable::*;

const MAX_HEIGHT: usize = 64;

/// Merkle tree, represented by layers of nodes (hashes) in the tree at each height.
#[derive(Clone, Debug)]
pub struct Tree {
    /// Levels of the tree from level 0 (leaves) to level h-1 (root).
    pub levels: Vec<Layer>,
}

impl Tree {
    /// Constructs a Merkle tree given an array.
    pub fn from_array(array: &[impl Hashable]) -> Result<Self, ()> {
        let mut tree = Self {
            levels: vec![Layer(array.iter().map(|h| hash_obj(h)).collect())],
        };

        while tree.top_layer().0.len() > 1 {
            tree.levels.push(tree.top_layer().up());
        }

        Ok(tree)
    }

    /// Returns the root hash of the Merkle tree.
    pub fn root(&self) -> CryptoHash {
        // Special case: commitment to zero-length array
        if self.levels[0].0.is_empty() {
            return CryptoHash([0; HASH_LEN]);
        }

        self.top_layer().0[0].clone()
    }

    /// Constructs a proof for some set of positions in the array that was used to construct the tree.
    pub fn prove(&self, idxs: &mut Vec<u64>) -> Result<Vec<CryptoHash>, ()> {
        const VALIDATE_PROOF: bool = false;

        if idxs.is_empty() {
            return Ok(Vec::new());
        }

        // Special case: commitment to zero-length array
        if self.levels.is_empty() {
            //return nil, fmt.Errorf("proving in zero-length commitment")
            return Err(());
        }

        idxs.sort_unstable();

        let mut pl = PartialLayer(Vec::new());
        for &pos in idxs.iter() {
            if pos >= self.levels[0].0.len() as u64 {
                //return nil, fmt.Errorf("pos %d larger than leaf count %d", pos, len(tree.levels[0]))
                return Err(());
            }

            // Discard duplicates
            if !pl.0.is_empty() && pl.0.last().unwrap().pos == pos {
                continue;
            }

            pl.0.push(LayerItem {
                pos,
                hash: self.levels[0].0[pos as usize].clone(),
            });
        }

        let mut s = Siblings {
            tree: self,
            hints: VecDeque::new(),
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
            let root_calculated = &pl.0[0];
            if root_calculated.pos != 0 || root_calculated.hash != self.top_layer().0[0] {
                //return nil, fmt.Errorf("internal error: root mismatch during proof")
                return Err(());
            }
        }

        Ok(s.hints.into())
    }

    /// Ensures that the positions in elems correspond to the respective hashes in a tree with the given root hash.
    /// The proof is expected to be the proof returned by `prove()`.
    pub fn verify(
        root: &CryptoHash,
        elems: HashMap<u64, CryptoHash>,
        proof: &[CryptoHash],
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

        pl.0.sort_by(|a, b| a.pos.cmp(&b.pos));

        let tree = Tree { levels: Vec::new() };
        let mut s = Siblings {
            tree: &tree,
            hints: proof.to_owned().into(),
        };

        let mut l = 0;
        while !s.hints.is_empty() || pl.0.len() > 1 {
            pl = pl.up(&mut s, l as u64, true)?;
            l += 1;

            if l > MAX_HEIGHT {
                //return fmt.Errorf("Verify exceeded 64 levels, more than 2^64 leaves not supported")
                return Err(());
            }
        }

        let root_calculated = pl.0[0].clone();
        if root_calculated.pos != 0 || root_calculated.hash != *root {
            //return fmt.Errorf("root mismatch")
            return Err(());
        }

        Ok(())
    }

    fn top_layer(&self) -> &Layer {
        &self.levels[self.levels.len() - 1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::FromIterator;

    use maplit::hashmap;
    use rand::{thread_rng, RngCore};

    #[test]
    fn build() {
        const SIZE: usize = 4;

        let a: Vec<String> = (0..SIZE).map(|i| format!("test{}", i).to_owned()).collect();
        let tree = Tree::from_array(&a).unwrap();
        assert_eq!(tree.levels.len(), 3);
        assert_eq!(tree.levels[0].0.len(), 4);
        assert_eq!(tree.levels[1].0.len(), 2);
        assert_eq!(tree.levels[2].0.len(), 1);
    }

    #[test]
    fn simple_proof() {
        const SIZE: usize = 4;

        let a: Vec<String> = (0..SIZE).map(|i| format!("test{}", i).to_owned()).collect();
        let tree = Tree::from_array(&a).unwrap();
        let root = tree.root();

        let proof = tree.prove(&mut vec![1]).unwrap();
        let elems = hashmap! {1 => hash_obj(&"test1".to_owned())};
        assert!(Tree::verify(&root, elems, &proof).is_ok());
    }

    #[test]
    fn full_test() {
        let mut rng = thread_rng();
        let junk = "junk".to_owned();

        for size in [0, 1, 2, 3, 4, 8, 16, 32, 64, 128, 256] {
            let a: Vec<String> = (0..size).map(|i| format!("test{}", i).to_owned()).collect();
            let tree = Tree::from_array(&a).unwrap();
            let root = tree.root();

            let mut allpos = (0..size).collect();
            let allmap =
                HashMap::from_iter((0..size).map(|i| (i, hash_obj(&a[i as usize]))).into_iter());

            for i in 0..size {
                let proof = tree.prove(&mut vec![i]).unwrap();
                let elems = hashmap! {i => hash_obj(&a[i as usize])};
                assert!(Tree::verify(&root, elems, &proof).is_ok());
                let elems = hashmap! {i => hash_obj(&junk)};
                assert!(Tree::verify(&root, elems, &proof).is_err());
            }

            let proof = tree.prove(&mut allpos).unwrap();
            assert!(Tree::verify(&root, allmap, &proof).is_ok());

            let elems = hashmap! {0 => hash_obj(&junk)};
            assert!(Tree::verify(&root, elems.clone(), &proof).is_err());
            assert!(Tree::verify(&root, elems, &Vec::new()).is_err());

            assert!(
                tree.prove(&mut vec![size]).is_err(),
                "no error when proving past the end"
            );
            let elems = hashmap! {size => hash_obj(&junk)};
            assert!(
                Tree::verify(&root, elems, &Vec::new()).is_err(),
                "no error when verifying past the end"
            );

            if size > 0 {
                let mut somepos = Vec::new();
                let mut somemap = HashMap::new();
                for _ in 0..10 {
                    let pos = rng.next_u64() % size;
                    somepos.push(pos);
                    somemap.insert(pos, hash_obj(&a[pos as usize]));
                }

                let proof = tree.prove(&mut somepos).unwrap();
                Tree::verify(&root, somemap, &proof).unwrap();
            }
        }
    }
}
