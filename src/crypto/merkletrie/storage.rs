// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;

use super::*;

/// Trait for supporting serializing tries into persistent storage.
pub trait Storage {
    fn store_node(&mut self, id: NodeID, content: &[u8]) -> Result<(), std::io::Error>;
    fn load_node(&mut self, id: NodeID) -> Result<Option<Vec<u8>>, std::io::Error>;
    fn current_storage_size(&self) -> usize;
}

impl Storage for sled::Tree {
    /// Stores a single node in this sled DB Tree.
    fn store_node(&mut self, id: NodeID, content: &[u8]) -> Result<(), std::io::Error> {
        if content.is_empty() {
            self.remove(id.to_be_bytes())?;
        } else {
            self.insert(id.to_be_bytes(), content)?;
        }
        Ok(())
    }

    /// Loads a single node from this sled DB Tree.
    fn load_node(&mut self, id: NodeID) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self.get(id.to_be_bytes()) {
            Ok(res) => match res {
                Some(p) => Ok(Some(p.to_vec())),
                None => Ok(None),
            },
            Err(_) => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        }
    }

    fn current_storage_size(&self) -> usize {
        0
    }
}

/// Fully functioning in-memory committer, supporting persistence of nodes.
#[derive(Default)]
pub struct InMemoryStorage {
    mem_store: HashMap<NodeID, Vec<u8>>,
}

impl Storage for InMemoryStorage {
    /// Stores a single node in an in-memory persistence.
    fn store_node(&mut self, id: NodeID, content: &[u8]) -> Result<(), std::io::Error> {
        if content.is_empty() {
            self.mem_store.remove(&id);
        } else {
            self.mem_store.insert(id, content.to_vec());
        }
        Ok(())
    }

    /// Loads a single node from an in-memory persistence.
    fn load_node(&mut self, id: NodeID) -> Result<Option<Vec<u8>>, std::io::Error> {
        match self.mem_store.get(&id) {
            Some(p) => Ok(Some(p.clone())),
            None => Ok(None),
        }
    }

    fn current_storage_size(&self) -> usize {
        let mut storage_size = 0;
        println!("num nodes in storage: {}", self.mem_store.values().count());
        for bytes in self.mem_store.values() {
            storage_size += bytes.len();
        }
        storage_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::crypto::hash;

    #[test]
    fn basic() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        // create 50000 hashes.
        let leaves = 50_000;
        let mut hashes = Vec::with_capacity(leaves);
        for i in 0..leaves {
            hashes.push(hash(&[
                (i % 256) as u8,
                ((i / 256) % 256) as u8,
                (i / 65536) as u8,
            ]));
        }

        for i in 0..leaves / 4 {
            trie.add(&hashes[i].0).unwrap();
        }
        //mt1.Commit()
        for i in leaves / 4..leaves / 2 {
            trie.add(&hashes[i].0).unwrap();
        }
        //releasedNodes, err := mt1.Evict(true)
        //require.NoError(t, err)
        //savedMemoryPageStorage := memoryPageStorage.Duplicate(false)
        //require.Equal(t, 19282, releasedNodes)
        for i in leaves / 2..leaves {
            trie.add(&hashes[i].0).unwrap();
        }

        //mt1Hash, _ := mt1.RootHash()

        //mt2, _ := MakeTrie(savedMemoryPageStorage, defaultTestMemoryConfig)

        //for i := len(hashes) / 2; i < len(hashes); i++ {
        //    mt2.Add(hashes[i][:])
        //}

        //mt2Hash, _ := mt2.RootHash()

        //require.Equal(t, mt1Hash, mt2Hash)
        //require.Equal(t, 137, len(memoryPageStorage.memStore)) // 137 pages.
        let storage_size = trie.cache.storage.current_storage_size();
        assert_eq!(1863648, storage_size) // 1,863,648 / 50,000 ~= 37 bytes/leaf.
                                          //stats, _ := mt1.GetStats()
                                          //require.Equal(t, leafsCount, int(stats.LeafCount))
                                          //require.Equal(t, 61926, int(stats.NodesCount))
    }
}
