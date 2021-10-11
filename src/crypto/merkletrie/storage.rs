// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;

use super::*;

/// Trait for supporting serializing tries into persistent storage.
pub trait Storage {
    fn store_node(&mut self, id: NodeID, content: &[u8]) -> Result<(), std::io::Error>;
    fn load_node(&mut self, id: NodeID) -> Result<Option<Vec<u8>>, std::io::Error>;
}

impl Storage for sled::Tree {
    /// Stores a single node in this sled DB Tree.
    fn store_node(&mut self, id: NodeID, content: &[u8]) -> Result<(), std::io::Error> {
        if content.is_empty() {
            self.remove(id.to_be_bytes());
        } else {
            self.insert(id.to_be_bytes(), content);
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
            Err(e) => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
    #[test]
    fn basic() {
        let mc = InMemoryPageStorage::default();
        mt1 = Trie::new(&mc, MemoryConfig::default());
        // create 50000 hashes.
        leafsCount := 50000
        hashes := make([]crypto.Digest, leafsCount)
        for i := 0; i < len(hashes); i++ {
            hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
        }

        for i := 0; i < len(hashes)/4; i++ {
            mt1.Add(hashes[i][:])
        }
        mt1.Commit()
        for i := len(hashes) / 4; i < len(hashes)/2; i++ {
            mt1.Add(hashes[i][:])
        }
        releasedNodes, err := mt1.Evict(true)
        require.NoError(t, err)
        savedMemoryPageStorage := memoryPageStorage.Duplicate(false)
        require.Equal(t, 19282, releasedNodes)
        for i := len(hashes) / 2; i < len(hashes); i++ {
            mt1.Add(hashes[i][:])
        }

        mt1Hash, _ := mt1.RootHash()

        mt2, _ := MakeTrie(savedMemoryPageStorage, defaultTestMemoryConfig)

        for i := len(hashes) / 2; i < len(hashes); i++ {
            mt2.Add(hashes[i][:])
        }

        mt2Hash, _ := mt2.RootHash()

        require.Equal(t, mt1Hash, mt2Hash)
        require.Equal(t, 137, len(memoryPageStorage.memStore)) // 137 pages.
        // find the size of all the storage.
        storageSize := 0
        for _, bytes := range memoryPageStorage.memStore {
            storageSize += len(bytes)
        }
        require.Equal(t, 2425675, storageSize) // 2,425,575 / 50,000 ~= 48 bytes/leaf.
        stats, _ := mt1.GetStats()
        require.Equal(t, leafsCount, int(stats.LeafCount))
        require.Equal(t, 61926, int(stats.NodesCount))
    }
    */
}
