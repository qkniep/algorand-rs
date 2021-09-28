// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::{TryFrom, TryInto};
use std::fmt;

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512Trunc256};
use thiserror::Error;

use crate::protocol;

/// Number of bytes in the preferred hash digest used here.
pub const HASH_LEN: usize = 32;

/// Represents a 32-byte (256-bit) value holding a hash digest.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoHash(pub [u8; HASH_LEN]);

#[derive(Error, Debug)]
pub enum HashError {
    #[error("invalid base32 encoding")]
    InvalidBase32(#[from] data_encoding::DecodeError),
    #[error("wrong length for hash: `{0}`")]
    WrongLength(usize),
}

/// A trait implemented by objects that can be turned into a sequence of bytes to be hashed.
/// It needs also to provide a type ID (HashID) to distinguish different types of objects.
pub trait Hashable {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>);

    fn hash_rep(&self) -> Vec<u8> {
        let (id, data) = self.to_be_hashed();
        [id.as_bytes(), &data].concat().to_vec()
    }
}

impl Hashable for String {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::MESSAGE, self.as_bytes().to_vec())
    }
}

impl CryptoHash {
    /// Returns the leading 64 bits (i.e. the first 8 bytes) of the digest and converts to uint64.
    pub fn trim_to_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[..8].try_into().unwrap())
    }

    /// Returns true iff the digest contains only zeros.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; HASH_LEN]
    }
}

// Display the digest as a human-readable Base32 string.
impl fmt::Display for CryptoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE32_NOPAD.encode(&self.0))
    }
}

/// DigestFromString converts a string to a CryptoHash
impl TryFrom<&str> for CryptoHash {
    type Error = HashError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let decoded = BASE32_NOPAD.decode(s.as_bytes())?;
        if decoded.len() != HASH_LEN {
            return Err(HashError::WrongLength(decoded.len()));
        }
        Ok(CryptoHash(decoded.try_into().unwrap()))
    }
}

/// Computes the SHA-512/256 hash of an array of bytes.
pub fn hash(data: &[u8]) -> CryptoHash {
    CryptoHash(Sha512Trunc256::digest(data)[..].try_into().unwrap())
}

/// Computes a hash of a Hashable object and its type.
pub fn hash_obj(obj: &impl Hashable) -> CryptoHash {
    hash(&obj.hash_rep())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, RngCore};

    #[test]
    fn encode_decode() {
        let bytes = b"test";
        let hash = hash(bytes);
        let s: &str = &hash.to_string();
        let recovered: CryptoHash = s.try_into().unwrap();
        assert_eq!(recovered, hash);
    }

    #[test]
    fn is_zero() {
        let mut h = CryptoHash::default();
        assert!(h.is_zero());

        let mut rng = thread_rng();
        rng.fill_bytes(&mut h.0);
        assert_eq!(h.is_zero(), false);
    }

    #[test]
    fn truncate_u64() {
        let h = CryptoHash::default();
        assert_eq!(h.trim_to_u64(), 0);

        // test compatibility with go-algorand
        let bytes = b"test";
        let h = hash(bytes);
        assert_eq!(h.trim_to_u64(), 0x870d5e4358fe373d);
    }
}
