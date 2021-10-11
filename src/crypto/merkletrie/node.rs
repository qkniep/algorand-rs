// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::cell::RefCell;
use std::io::Read;

use integer_encoding::{VarIntReader, VarIntWriter};

use super::*;
use crate::crypto::hashable::{hash, HASH_LEN};

#[derive(Clone, Debug, Default)]
pub struct Node {
    /// ID to find parent node in memory/storage (None for root node).
    pub parent: Option<NodeID>,
    /// Makes root calculation more efficient by not recalculating hashes of unchanged subtrees.
    pub dirty: bool,
    pub hash: Vec<u8>,
    pub children: Option<[Option<NodeID>; 256]>,
}

impl Node {
    /// Returns true iff the current node is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.children.is_none()
    }

    /// Searches the trie for the element, recursively.
    pub fn find(&self, cache: &mut MerkleTrieCache, d: &[u8]) -> Result<bool, CacheError> {
        if self.is_leaf() {
            return Ok(d == self.hash);
        }
        if let Some(child_id) = self.children.unwrap()[usize::from(d[0])] {
            let child_node = cache.get_node(child_id)?.clone();
            child_node.find(cache, &d[1..])
        } else {
            Ok(false)
        }
    }

    /// Adds an element to the sub-trie.
    /// Assumption: We know that the key is absent from the tree.
    pub fn add(
        &self,
        cache: &mut MerkleTrieCache,
        d: &[u8],
        path: &[u8],
    ) -> Result<NodeID, CacheError> {
        // allocate a new node to replace the current one.
        if self.is_leaf() {
            // find the diff index:
            let mut idiff = 0;
            while self.hash[idiff] == d[idiff] {
                idiff += 1;
            }

            let (mut cur_child_node, cur_child_node_id) = cache.allocate_new_node();
            cur_child_node.hash = self.hash[idiff + 1..].to_vec();
            cache.set_node(cur_child_node_id, cur_child_node)?;

            let (mut new_child_node, new_child_node_id) = cache.allocate_new_node();
            new_child_node.hash = d[idiff + 1..].to_vec();
            cache.set_node(new_child_node_id, new_child_node)?;

            let (mut pnode, mut node_id) = cache.allocate_new_node();

            pnode.parent = self.parent;
            pnode.dirty = true;
            let mut children = [None; 256];
            children[usize::from(d[idiff])] = Some(new_child_node_id);
            children[usize::from(self.hash[idiff])] = Some(cur_child_node_id);
            pnode.children = Some(children);
            //pnode.children = Some([None; 256]);
            //pnode.children.unwrap()[usize::from(d[idiff])] = Some(new_child_node_id);
            //pnode.children.unwrap()[usize::from(self.hash[idiff])] = Some(cur_child_node_id);
            pnode.hash = [path, &d[..idiff]].concat().to_vec();
            cache.set_node(node_id, pnode.clone())?;

            for i in (0..idiff).rev() {
                // create a parent node for pnode.
                let (mut pnode2, node_id2) = cache.allocate_new_node();
                let tmp_parent = pnode.parent;
                pnode.parent = Some(node_id2);
                pnode2.parent = tmp_parent;
                pnode2.dirty = true;
                pnode2.children = Some([None; 256]);
                pnode2.children.unwrap()[usize::from(d[i])] = Some(node_id);
                pnode2.hash = [path, &d[..i]].concat().to_vec();

                cache.set_node(node_id, pnode)?;
                cache.set_node(node_id2, pnode2.clone())?;

                pnode = pnode2;
                node_id = node_id2;
            }
            return Ok(node_id);
        }

        let (mut pnode, node_id) =
            if self.children.is_none() || self.children.unwrap()[usize::from(d[0])].is_none() {
                // no such child.
                let (mut child_node, child_node_id) = cache.allocate_new_node();
                child_node.hash = d[1..].to_vec();
                cache.set_node(child_node_id, child_node)?;

                let (mut pnode, node_id) = cache.allocate_new_node();
                pnode.parent = self.parent;
                pnode.dirty = true;
                let mut children = self.children.clone().unwrap_or([None; 256]);
                children[usize::from(d[0])] = Some(child_node_id);
                pnode.children = Some(children);
                (pnode, node_id)
            } else {
                // there is already a child there.
                let cur_node_id = self.children.unwrap()[usize::from(d[0])].unwrap();
                let child_node = cache.get_node(cur_node_id)?.clone();
                let updated_child = child_node.add(cache, &d[1..], &[path, &[d[0]]].concat())?;

                let (mut pnode, node_id) = cache.allocate_new_node();
                pnode.parent = self.parent;
                pnode.dirty = true;
                let mut children = self.children.clone().unwrap();
                children[usize::from(d[0])] = Some(updated_child);
                pnode.children = Some(children);
                (pnode, node_id)
            };
        pnode.hash = path.to_vec();
        cache.set_node(node_id, pnode)?;
        Ok(node_id)
    }

    /// Calculate the hash of the non-leaf nodes when this function is called,
    // the hashes of all the child node are expected to have been calculated already.
    // This is achieved by doing the following:
    //   1. all node id allocations are done in incremental monolitic order, from the bottom up
    //   2. hash calculations are being doing in node id incremental ordering
    pub fn calculate_hash(&mut self, cache: &mut MerkleTrieCache) -> Result<(), CacheError> {
        thread_local! {
            static HASH_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(HASH_LEN * 256));
        }

        if self.is_leaf() || !self.dirty {
            return Ok(());
        }

        // recursively calculate hashes (depth first)
        if let Some(children) = self.children {
            for child_id in &children {
                if let Some(id) = child_id {
                    let mut child_node = cache.get_node(*id)?;
                    if !child_node.is_leaf() && child_node.dirty {
                        child_node.calculate_hash(cache)?;
                        cache.set_node(*id, child_node)?;
                    }
                }
            }
        }

        let mut path = self.hash.clone();
        HASH_BUF.with(|buf| {
            let mut accumulator = buf.borrow_mut(); // use a preallocated storage and reuse the storage to avoid reallocation.
            accumulator.clear();
            accumulator.push(path.len() as u8); // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
            accumulator.append(&mut path);
            if let Some(children) = self.children {
                for (i, child_id) in children.iter().enumerate() {
                    if child_id.is_none() {
                        continue;
                    }
                    let child_node = cache.get_node(child_id.unwrap())?;
                    match child_node.is_leaf() {
                        true => accumulator.push(0),
                        false => accumulator.push(1),
                    }
                    accumulator.push(child_node.hash.len() as u8); // we add this string length before the actual string so it could get "decoded"; in practice, it makes a good domain separator.
                    accumulator.push(i as u8); // adding the first byte of the child
                    accumulator.extend_from_slice(&child_node.hash) // adding the reminder of the child
                }
            }
            self.hash = hash(&accumulator).0.to_vec();
            self.dirty = false;
            Ok(())
        })
    }

    /// Removes an element from the sub-trie function remove is called only on non-leaf nodes.
    /// Assumption: We know that the key is already included in the tree.
    pub fn remove(
        &self,
        cache: &mut MerkleTrieCache,
        key: &[u8],
        path: &[u8],
    ) -> Result<NodeID, CacheError> {
        // allocate a new node to replace the current one.
        let child_id = self.children.unwrap()[usize::from(key[0])].unwrap();
        let child_node = cache.get_node(child_id)?.clone();
        let (mut pnode, node_id) = if child_node.is_leaf() {
            let (pnode, node_id) = cache.allocate_new_node();
            pnode.children.unwrap()[usize::from(key[0])] = None;
            (pnode, node_id)
        } else {
            let updated_child_node_id =
                child_node.remove(cache, &key[1..], &[path, &[key[0]]].concat())?;

            let (mut pnode, node_id) = cache.allocate_new_node();
            pnode.children = self.children.clone();
            pnode.children.unwrap()[usize::from(key[0])] = Some(updated_child_node_id);
            (pnode, node_id)
        };

        let (mut hash_idx, mut child_id, mut num_children) = (0, 0, 0);
        for (i, id) in pnode.children.unwrap().iter().enumerate() {
            if let Some(cid) = id {
                hash_idx = i;
                child_id = *cid;
                num_children += 1;
            }
        }

        // at this point, we might end up with a single leaf child. collapse that.
        if num_children == 1 {
            let child_node = cache.get_node(child_id)?;
            if child_node.is_leaf() {
                // convert current node into a leaf.
                pnode.hash = [&[hash_idx as u8], child_node.hash.as_slice()].concat();
                cache.delete_node(child_id);
                pnode.children = None;
            }
        }
        if !pnode.is_leaf() {
            pnode.hash = path.to_vec();
        }
        Ok(node_id)
    }

    /// Serializes the content of the node into the buffer.
    /// Returns the number of bytes written in the process.
    pub fn serialize(&self, buf: &mut Vec<u8>) -> i32 {
        let mut w = buf.write_varint(self.hash.len() as u64).unwrap();
        buf.extend_from_slice(&self.hash);
        w += self.hash.len();
        if self.is_leaf() {
            buf.push(0); // leaf
            return w as i32 + 1;
        }
        // non-leaf
        buf.push(1); // non-leaf
        w += 1;
        // store all the children, and terminate with a null.
        for (hash_idx, child_id) in self.children.unwrap().iter().enumerate() {
            if let Some(cid) = child_id {
                buf.push(hash_idx as u8);
                w += 1;
                let x = buf.write_varint(*cid).unwrap();
                w += x;
            }
        }
        //buf[w] = self.children.unwrap().last().unwrap().hash_index;
        w as i32 + 1
    }

    /// Deserializes a node from a byte slice.
    pub fn deserialize(buf: &[u8]) -> Option<Node> {
        let mut cursor = std::io::Cursor::new(buf);
        let mut n = Node::default();
        let hash_length = cursor.read_varint().ok()?;
        n.hash = vec![0; hash_length];
        cursor.read_exact(&mut n.hash);
        let mut is_inner = 0_u8;
        cursor.read_exact(std::slice::from_mut(&mut is_inner));
        if is_inner == 0 {
            return None;
        }
        n.children = Some([None; 256]);
        let mut child_index = 0_u8;
        while cursor.position() < buf.len() as u64 {
            cursor.read_exact(std::slice::from_mut(&mut child_index));
            let node_id = cursor.read_varint().ok()?;
            n.children.unwrap()[usize::from(child_index)] = Some(node_id);
        }
        Some(n)
    }

    pub fn get_child_count(&self) -> u64 {
        let mut num_children = 0;
        for id in &self.children.unwrap() {
            if id.is_some() {
                num_children += 1;
            }
        }
        num_children
    }
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_serialization() {
        let mc InMemoryCommitter
        memConfig := defaultTestMemoryConfig
        memConfig.CachedNodesCount = 1000
        mt1, _ := MakeTrie(&memoryCommitter, memConfig)
        // create 1024 hashes.
        leafsCount := 1024
        hashes := make([]crypto.Digest, leafsCount)
        for i := 0; i < len(hashes); i++ {
            hashes[i] = crypto.Hash([]byte{byte(i % 256), byte((i / 256) % 256), byte(i / 65536)})
        }

        for i := 0; i < len(hashes); i++ {
            mt1.Add(hashes[i][:])
        }
        for _, page := range mt1.cache.pageToNIDsPtr {
            for _, pnode := range page {
                buf := make([]byte, 10000)
                consumedWrite := pnode.serialize(buf[:])
                outNode, consumedRead := deserializeNode(buf[:])
                require.Equal(t, consumedWrite, consumedRead)
                require.Equal(t, pnode.leaf(), outNode.leaf())
                require.Equal(t, len(pnode.children), len(outNode.children))
                reencodedBuffer := make([]byte, 10000)
                renecodedConsumedWrite := outNode.serialize(reencodedBuffer[:])
                require.Equal(t, consumedWrite, renecodedConsumedWrite)
                require.Equal(t, buf, reencodedBuffer)
            }
        }
    }
}
*/
