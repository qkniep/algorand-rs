// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Implementation of a cache storing `Node`s in pages.
//! It implements the Clock replacement strategy.
//! Acts as a caching backend to a Merkle `Trie` object.
//! The `MerkleTrieCache` object in turn has a `PageStorage` as persistency backend.

use std::collections::HashMap;

use thiserror::Error;

use super::*;

#[derive(Debug, Error)]
pub enum CacheError {
    /// When a request is made for a specific node ID and it can be found neither in cache nor in persistent storage.
    #[error("loaded page is missing a node")]
    MissingNode,
    #[error("error encountered while decoding node")]
    NodeDecodingFailure,
    #[error("access to the underlying storage failed: {0}")]
    StorageAccessFailed(#[from] std::io::Error),
}

pub struct MerkleTrieCache {
    /// Storage backend for the cache (memory, database, ...).
    pub storage: Box<dyn Storage>,
    cache: HashMap<NodeID, Node>,
    next_node_id: NodeID,
}

impl MerkleTrieCache {
    /// Performs initialization for the cache.
    pub fn new(storage: impl Storage + 'static) -> Self {
        Self {
            storage: Box::new(storage),
            cache: HashMap::new(),
            next_node_id: 0,
        }
    }

    ///
    pub fn allocate_new_node(&mut self) -> (Node, NodeID) {
        let id = self.next_node_id;
        self.next_node_id += 1;
        let new_node = Node::default();
        self.cache.insert(id, new_node.clone());
        (new_node, id)
    }

    /// Retrieves the given node by its identifier, loading it from storage if it cannot be found in cache,
    /// and returning an error if it's neither in cache nor in storage.
    pub fn get_node(&mut self, id: NodeID) -> Result<Node, CacheError> {
        if !self.cache.contains_key(&id) {
            match self.storage.load_node(id)? {
                None => return Err(CacheError::MissingNode),
                Some(node_data) => {
                    match Node::deserialize(&node_data) {
                        None => return Err(CacheError::NodeDecodingFailure),
                        Some(node) => self.cache.insert(id, node),
                    };
                }
            }
        }
        Ok(self.cache.get(&id).unwrap().clone())
    }

    pub fn set_node(&mut self, id: NodeID, node: Node) -> Result<(), CacheError> {
        let mut buf = Vec::new();
        node.serialize(&mut buf);
        self.cache.insert(id, node);
        self.storage.store_node(id, &buf);
        Ok(())
    }

    /// Marks the given node to be deleted, or (if it was never flushed) deletes it right away.
    // TODO adapt once we support transactions again
    pub fn delete_node(&mut self, id: NodeID) {
        self.cache.remove(&id);
        self.storage.store_node(id, &[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
