// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use integer_encoding::{VarIntReader, VarIntWriter};
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
    cache: MerkleTrieCache,
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

        let pnode = self.cache.get_node(self.root.unwrap())?.clone();
        let found = pnode.find(&mut self.cache, d)?;
        if found {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
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
}
