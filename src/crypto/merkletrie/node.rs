// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::cell::RefCell;
use std::io::Read;

use integer_encoding::{VarIntReader, VarIntWriter};

use super::*;
use crate::crypto::hashable::{hash, HASH_LEN};

#[derive(Clone, Debug, Default)]
pub struct Node {
    /// Makes root calculation more efficient by not recalculating hashes of unchanged subtrees.
    // TODO check hash.len() < 32 and !is_leaf() instead???
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
            let child_node = cache.get_node(child_id)?;
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

            // TODO do not `allocate_new_node` where go-algorand uses `refurbishNode`,
            //      instead just update the node via `set_node`.
            let (mut cur_child_node, cur_child_id) = cache.allocate_new_node();
            cur_child_node.hash = self.hash[idiff + 1..].to_vec();
            cache.set_node(cur_child_id, cur_child_node)?;

            let (mut new_child_node, new_child_id) = cache.allocate_new_node();
            new_child_node.hash = d[idiff + 1..].to_vec();
            cache.set_node(new_child_id, new_child_node)?;

            let (mut pnode, mut id) = cache.allocate_new_node();

            pnode.dirty = true;
            pnode.children = Some([None; 256]);
            pnode.children.as_mut().unwrap()[usize::from(d[idiff])] = Some(new_child_id);
            pnode.children.as_mut().unwrap()[usize::from(self.hash[idiff])] = Some(cur_child_id);
            pnode.hash = [path, &d[..idiff]].concat().to_vec();
            cache.set_node(id, pnode.clone())?;

            for i in (0..idiff).rev() {
                // create a parent node for pnode.
                let (mut pnode2, id2) = cache.allocate_new_node();
                pnode2.dirty = true;
                pnode2.children = Some([None; 256]);
                pnode2.children.as_mut().unwrap()[usize::from(d[i])] = Some(id);
                pnode2.hash = [path, &d[..i]].concat().to_vec();
                cache.set_node(id2, pnode2)?;

                id = id2;
            }
            return Ok(id);
        }

        let (mut pnode, id) = if self.children.unwrap()[usize::from(d[0])].is_none() {
            // no such child.
            let (mut child_node, child_id) = cache.allocate_new_node();
            child_node.hash = d[1..].to_vec();
            cache.set_node(child_id, child_node)?;

            let (mut pnode, id) = cache.allocate_new_node();
            pnode.dirty = true;
            pnode.children = self.children;
            pnode.children.as_mut().unwrap()[usize::from(d[0])] = Some(child_id);
            (pnode, id)
        } else {
            // there is already a child there.
            let cur_id = self.children.unwrap()[usize::from(d[0])].unwrap();
            let mut child_node = cache.get_node(cur_id)?;
            let updated_child = child_node.add(cache, &d[1..], &[path, &[d[0]]].concat())?;

            child_node.dirty = true;
            child_node.children = self.children;
            child_node.children.as_mut().unwrap()[usize::from(d[0])] = Some(updated_child);
            (child_node, cur_id)
        };
        pnode.hash = path.to_vec();
        cache.set_node(id, pnode)?;
        Ok(id)
    }

    /// Calculate the hash of the dirty non-leaf nodes when this function is called,
    pub fn calculate_hash(&mut self, cache: &mut MerkleTrieCache) -> Result<(), CacheError> {
        thread_local! {
            static HASH_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::with_capacity(HASH_LEN * 256));
        }

        if self.is_leaf() || !self.dirty {
            return Ok(());
        }

        // recursively calculate hashes (depth first)
        for id in self.children.into_iter().flatten().flatten() {
            let mut child_node = cache.get_node(id)?;
            if !child_node.is_leaf() && child_node.dirty {
                child_node.calculate_hash(cache)?;
                cache.set_node(id, child_node)?;
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

    /// Removes an element from the subtrie (only called on non-leaf nodes).
    /// Assumption: We know that the key is already included in the tree.
    pub fn remove(
        &self,
        cache: &mut MerkleTrieCache,
        key: &[u8],
        path: &[u8],
    ) -> Result<NodeID, CacheError> {
        // allocate a new node to replace the current one.
        let nid = self.children.unwrap()[usize::from(key[0])].unwrap();
        let mut node = cache.get_node(nid)?;
        if node.is_leaf() {
            node.children = self.children;
            node.children.as_mut().unwrap()[usize::from(key[0])] = None;
        } else {
            let updated_child_id = node.remove(cache, &key[1..], &[path, &[key[0]]].concat())?;

            node.children = self.children;
            node.children.as_mut().unwrap()[usize::from(key[0])] = Some(updated_child_id);
        };

        // find the only child, if there is only one
        let (mut hash_idx, mut child_id, mut num_children) = (0, 0, 0);
        for (i, id) in node.children.unwrap().iter().enumerate() {
            if let Some(cid) = id {
                hash_idx = i;
                child_id = *cid;
                num_children += 1;
                if num_children > 1 {
                    break;
                }
            }
        }

        // at this point, we might end up with a single leaf child. collapse that.
        if num_children == 1 {
            let child_node = cache.get_node(child_id)?;
            if child_node.is_leaf() {
                // convert current node into a leaf.
                node.hash = [&[hash_idx as u8], child_node.hash.as_slice()].concat();
                cache.delete_node(child_id)?;
                node.children = None;
                node.dirty = false;
            }
        }
        if !node.is_leaf() {
            node.hash = path.to_vec();
            node.dirty = true;
        }

        cache.set_node(nid, node)?;
        Ok(nid)
    }

    /// Serializes the content of the node into the buffer.
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.write_varint(self.hash.len() as u64).unwrap();
        buf.extend_from_slice(&self.hash);
        if self.is_leaf() {
            buf.push(0);
            return;
        }

        buf.push(1);
        for (i, child_id) in self.children.unwrap().iter().enumerate() {
            if let Some(cid) = child_id {
                buf.push(i as u8);
                buf.write_varint(*cid).unwrap();
            }
        }
    }

    /// Deserializes a node from a byte slice.
    pub fn deserialize(buf: &[u8]) -> Option<Node> {
        let mut cursor = std::io::Cursor::new(buf);
        let mut n = Node::default();
        let hash_length = cursor.read_varint().ok()?;
        n.hash = vec![0; hash_length];
        cursor.read_exact(&mut n.hash).ok()?;
        let mut is_inner = 0_u8;
        cursor
            .read_exact(std::slice::from_mut(&mut is_inner))
            .ok()?;
        if is_inner == 1 {
            n.children = Some([None; 256]);
            let mut child_index = 0_u8;
            while cursor.position() < buf.len() as u64 {
                cursor
                    .read_exact(std::slice::from_mut(&mut child_index))
                    .ok()?;
                let id = cursor.read_varint().ok()?;
                n.children.as_mut().unwrap()[usize::from(child_index)] = Some(id);
            }
        }
        Some(n)
    }

    pub fn get_child_count(&self) -> u64 {
        if self.children.is_none() {
            return 0;
        }

        let mut num_children = 0;
        for id in &self.children.unwrap() {
            if id.is_some() {
                num_children += 1;
            }
        }
        num_children
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    #[test]
    fn node_serialization() {
        let storage = InMemoryStorage::default();
        let mut trie = Trie::new(storage);

        // insert 1024 hashes.
        let leaves = 1024;
        for i in 0..leaves {
            let h = hash(&[(i % 256) as u8, ((i / 256) % 256) as u8, (i / 65536) as u8]);
            trie.add(&h.0).unwrap();
        }

        let mut to_visit: VecDeque<NodeID> = vec![trie.root.unwrap()].into();
        while !to_visit.is_empty() {
            let mut buf = Vec::new();
            let id = to_visit.pop_front().unwrap();
            let node = trie.cache.get_node(id).unwrap();

            node.serialize(&mut buf);
            let out_node = Node::deserialize(&buf).unwrap();
            assert_eq!(node.is_leaf(), out_node.is_leaf());
            assert_eq!(node.get_child_count(), out_node.get_child_count());

            let mut buf2 = Vec::new();
            out_node.serialize(&mut buf2);
            assert_eq!(buf.len(), buf2.len());
            assert_eq!(buf, buf2);

            if let Some(children) = node.children {
                for child_id in children {
                    if let Some(id) = child_id {
                        to_visit.push_back(id);
                    }
                }
            }
        }
    }
}
