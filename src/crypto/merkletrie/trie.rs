// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use thiserror::Error;

use super::*;
use crate::crypto::hashable::*;

/// Node ID used as address (think of a virtual memory address)
pub type NodeID = u64;

pub const NODE_ID_BASE: NodeID = 0x4160;
/// Serialized size of the biggest node.
/// Used for memory preallocation before serializing.
pub const MAX_NODE_SERIALIZED_SIZE: usize = 3000;

/// Version of the encoded trie.
pub const MERKLE_TRIE_VERSION: u64 = 0x1000000010000000;
/// Version of the encoded node.
pub const NODE_PAGE_VERSION: u64 = 0x1000000010000000;

#[derive(Debug, Error)]
pub enum TrieError {
    #[error("error encountered while decoding root page")]
    RootPageDecodingFailure(#[from] std::io::Error),
    #[error("the decoded root page had a wrong version")]
    RootPageVersionMismatch,
    /// When an element is being added/removed from the trie that doesn't align with the trie's previous elements length.
    #[error("mismatching element length")]
    ElementLengthMismatch,
    /// When you try to provide an existing trie a storage with a different page size than it was originally created with.
    #[error("mismatching page size")]
    PageSizeMismatch,
    /// The tree was modified and `evict` was called with `commit=false`.
    #[error("unable to evict as pending commits are available")]
    UnableToEvictPendingCommits,
    #[error("failed while accessing the underlying page cache")]
    CacheAccessError(#[from] CacheError),
}

/// Merkle trie intended to efficiently calculate the merkle root of unordered elements.
pub struct Trie {
    pub root: Option<NodeID>,
    pub cache: MerkleTrieCache,
    /// Size of the node values in bytes, all values must be the same size.
    /// This is set automatically upon insertion of the first node.
    element_length: u32,
}

impl Trie {
    /// Initializes a new trie, given a storage backend instance and memory configuration for the cache.
    pub fn new(storage: impl Storage + 'static) -> Self {
        Self {
            root: None,
            cache: MerkleTrieCache::new(storage),
            element_length: 0,
        }
    }

    /// Returns the root hash of all the elements in the trie.
    pub fn root_hash(&mut self) -> Result<CryptoHash, TrieError> {
        match self.root {
            None => Ok(CryptoHash::default()),
            Some(root_id) => {
                let mut root = self.cache.get_node(root_id)?;
                root.calculate_hash(&mut self.cache)?;
                self.cache.set_node(root_id, root.clone())?;
                match root.is_leaf() {
                    true => Ok(hash(&[&[0], root.hash.as_slice()].concat())),
                    false => Ok(hash(&[&[1], root.hash.as_slice()].concat())),
                }
            }
        }
    }

    /// Adds the given hash to the trie, if it does not exist yet.
    /// Returns false if the item already exists.
    pub fn add(&mut self, d: &[u8]) -> Result<bool, TrieError> {
        if self.root == None {
            let (mut pnode, id) = self.cache.allocate_new_node();
            self.root = Some(id);
            //self.cache.commit_transaction();
            pnode.hash = d.to_vec();
            self.cache.set_node(id, pnode).unwrap();
            self.element_length = d.len() as u32;
            return Ok(true);
        }

        let pnode = self.cache.get_node(self.root.unwrap())?;
        if pnode.find(&mut self.cache, d)? {
            return Ok(false);
        }

        //self.cache.begin_transaction(&mut self);
        match pnode.add(&mut self.cache, d, &Vec::new()) {
            Ok(updated_root) => {
                self.cache.delete_node(self.root.unwrap());
                self.root = Some(updated_root);
                //self.cache.commit_transaction();
                Ok(true)
            }
            Err(e) => {
                //self.cache.rollback_transaction(&mut self);
                Err(TrieError::CacheAccessError(e))
            }
        }
    }

    /// Removes the given hash from the trie, if it does exist.
    /// Returns false if the item did not exist.
    pub fn delete(&mut self, d: &[u8]) -> Result<bool, TrieError> {
        if self.root.is_none() {
            return Ok(false);
        } else if d.len() != self.element_length as usize {
            return Err(TrieError::ElementLengthMismatch);
        }
        let pnode = self.cache.get_node(self.root.unwrap())?;
        if !pnode.find(&mut self.cache, d)? {
            return Ok(false);
        }
        //mt.cache.beginTransaction()
        if pnode.is_leaf() {
            // remove the root.
            self.cache.delete_node(self.root.unwrap())?;
            self.root = None;
            //self.cache.commitTransaction()
            self.element_length = 0;
            return Ok(true);
        }
        match pnode.remove(&mut self.cache, d, &[]) {
            Err(e) => {
                //self.cache.rollbackTransaction()
                Err(TrieError::CacheAccessError(e))
            }
            Ok(updated_root) => {
                self.cache.delete_node(self.root.unwrap())?;
                //self.cache.commitTransaction()
                self.root = Some(updated_root);
                Ok(true)
            }
        }
    }

    fn print(&mut self) {
        //print!("Root: {:?}", self.root);
        print!("Root: {:?}", self.root.is_some());
        if let Some(root_id) = self.root {
            self.print_node(0, root_id, 0);
        }
    }

    fn print_node(&mut self, index: u8, id: NodeID, depth: u32) {
        let node = self.cache.get_node(id).unwrap();
        for _ in 0..depth {
            print!("    ");
        }
        //print!("[{}] -> {}, ", index, id);
        print!("[{}] -> ", index);
        if node.is_leaf() {
            println!("hash {:?}", node.hash);
            return;
        }
        println!("{} children", node.get_child_count());
        for (i, child) in node.children.unwrap().iter().enumerate() {
            if child.is_none() {
                continue;
            }
            self.print_node(i as u8, child.unwrap(), depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{seq::SliceRandom, thread_rng};

    #[test]
    fn go_compatibility() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        trie.add(&hash(&[0_u8]).0).unwrap();
        assert_eq!(
            &trie.root_hash().unwrap().to_string(),
            "ZZLO4PKXJPOWHFV2BECUMB6FOWJMX73AHJTPWXE5Q4D42PHAQB3Q"
        );

        trie.add(&hash(&[1_u8]).0).unwrap();
        assert_eq!(
            &trie.root_hash().unwrap().to_string(),
            "YBK7KNS6ZAXRCP2IBCYP3ALTTMGW7AIZUPC4NK3SBMYL4DAH6YKQ"
        );

        trie.add(&hash(&[2_u8]).0).unwrap();
        println!(
            "[{}]: {:?}",
            trie.root.unwrap(),
            trie.cache.get_node(trie.root.unwrap()).unwrap()
        );
        assert_eq!(
            &trie.root_hash().unwrap().to_string(),
            "JF2ICIVIQ42MIBPODQZVBADT43WYF47VTDXV2BTHSMO4DLOIEQXQ"
        );

        trie.add(&hash(&[3_u8]).0).unwrap();
        assert_eq!(
            &trie.root_hash().unwrap().to_string(),
            "GEEOOP2Q6TG46OWIHNYX2R6TKHJ64SMZBKFWA4DPFK7B2W2OPCLQ"
        );
        let mut hash4 = hash(&[4_u8]).0;
        hash4[0] = 5;
        trie.add(&hash4).unwrap();
        assert_eq!(
            &trie.root_hash().unwrap().to_string(),
            "UOT7QFKDJKXHMKESLG2L2YRHVTBIOP7NMCZUKAYBDRAWPMEPERHQ"
        );
    }

    #[test]
    fn add_remove() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        // create 1,000 hashes.
        let leaves = 1000;
        let mut hashes = Vec::with_capacity(1000);
        for i in 0..leaves {
            hashes.push(hash(&[(i % 256) as u8, (i / 256) as u8]));
        }

        let mut roots_while_adding = Vec::with_capacity(leaves);
        for hash in &hashes {
            let res = trie.add(&hash.0);
            assert_eq!(res.unwrap(), true);
            roots_while_adding.push(trie.root_hash().unwrap());
            //stats, _ := mt.GetStats()
            //require.Equal(t, i+1, int(stats.LeafCount))
        }

        //stats, _ := mt.GetStats()
        //require.Equal(t, len(hashes), int(stats.LeafCount))
        //require.Equal(t, 4, int(stats.Depth))
        //require.Equal(t, 10915, int(stats.NodesCount))
        //require.Equal(t, 1135745, int(stats.Size))
        //require.True(t, int(stats.NodesCount) > len(hashes))
        //require.True(t, int(stats.NodesCount) < 2*len(hashes))

        let final_root_hash = trie.root_hash().unwrap();

        for i in (0..leaves).rev() {
            let root_hash = trie.root_hash().unwrap();
            assert_eq!(root_hash, roots_while_adding[i], "i={}", i);
            let res = trie.delete(&hashes[i].0);
            assert_eq!(res.unwrap(), true, "i={}", i);
        }

        let root_hash = trie.root_hash().unwrap();
        assert_eq!(root_hash, CryptoHash::default());
        //stats, _ = mt.GetStats()
        //require.Equal(t, 0, int(stats.LeafCount))
        //require.Equal(t, 0, int(stats.Depth))

        // add the items in a different order.
        let mut rng = thread_rng();
        hashes.shuffle(&mut rng);
        for hash in &hashes {
            let res = trie.add(&hash.0);
            assert_eq!(res.unwrap(), true);
        }

        let rand_order_root_hash = trie.root_hash().unwrap();
        assert_eq!(rand_order_root_hash, final_root_hash);
    }

    #[test]
    fn random_add_remove() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        // create 10,000 hashes.
        let mut hashes_to_add = Vec::new();
        for i in 0..10_000 {
            hashes_to_add.push(hash(&[(i % 256) as u8, (i / 256) as u8]));
        }
        let mut hashes_to_remove = Vec::new();

        let mut add_next = true; // true: add, false: remove
        for i in 0..100_000 {
            let curr_hash: CryptoHash;
            if add_next && !hashes_to_add.is_empty() || hashes_to_remove.is_empty() {
                // pick an item to add:
                let mut semi_random_idx = hashes_to_add[0].0[0] as usize
                    + hashes_to_add[0].0[1] as usize * 256
                    + hashes_to_add[0].0[3] as usize * 65536
                    + i;
                semi_random_idx %= hashes_to_add.len();
                curr_hash = hashes_to_add.remove(semi_random_idx);
                assert_eq!(trie.add(&curr_hash.0).unwrap(), true);
                hashes_to_remove.push(curr_hash.clone());
            } else {
                // pick an item to remove:
                let mut semi_random_idx = hashes_to_remove[0].0[0] as usize
                    + hashes_to_remove[0].0[1] as usize * 256
                    + hashes_to_remove[0].0[3] as usize * 65536
                    + i;
                semi_random_idx %= hashes_to_remove.len();
                curr_hash = hashes_to_remove.remove(semi_random_idx);
                assert_eq!(trie.delete(&curr_hash.0).unwrap(), true);
                hashes_to_add.push(curr_hash.clone());
            }
            add_next = curr_hash.0[0] > 128;
            if i % (1 + curr_hash.0[0] as usize) == 42 {
                //trie.commit().unwrap();
                //verifyCacheNodeCount(t, mt)
            }
        }
    }

    #[test]
    fn free_unused_nodes() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        // create 50,000 hashes.
        let leaves = 50_000;
        let mut hashes = Vec::with_capacity(leaves);
        for i in 0..leaves {
            hashes.push(hash(&[
                (i % 256) as u8,
                ((i / 256) % 256) as u8,
                (i / 65536) as u8,
            ]));
        }

        // add all nodes once
        for i in 0..leaves {
            trie.add(&hashes[i].0).unwrap();
        }
        let storage_size_before = trie.cache.storage.current_storage_size();
        assert_ne!(storage_size_before, 0);

        // remove all nodes, and see if all nodes were actually deleted
        for i in 0..leaves {
            trie.delete(&hashes[i].0).unwrap();
        }
        let storage_size_empty = trie.cache.storage.current_storage_size();
        assert_eq!(trie.root.is_none(), true);
        assert_eq!(storage_size_empty, 0);
    }
}
