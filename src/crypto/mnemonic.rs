// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! An implementation of

use std::convert::TryInto;
use std::fs::File;
use std::io::{BufRead, BufReader};

use lazy_static::lazy_static;
use sha2::{Digest, Sha512Trunc256};

const BITS_PER_WORD: usize = 11;
const MNEMONIC_LEN_WORDS: usize = 25;
const KEY_LEN_BYTES: usize = 32;

lazy_static! {
    pub static ref WORDS: Vec<String> = load_mnemonic_file();
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicError {
    WrongMnemonicLen(usize),
    InvalidWordInMnemonic(String),
    WrongChecksum,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::WrongMnemonicLen(len) => {
                write!(
                    f,
                    "mnemonic must be {} words long but was {}",
                    MNEMONIC_LEN_WORDS, len
                )
            }
            Self::InvalidWordInMnemonic(word) => {
                write!(f, "invalid mnemonic: {} is not in the word list", word)
            }
            Self::WrongChecksum => write!(f, "failed to validate checksum"),
        }
    }
}

/// Converts a key into a mnemonic word list.
fn key_to_mnemonic(key: [u8; KEY_LEN_BYTES]) -> Vec<String> {
    let mut mnemonic: Vec<String> = to_base11(&key)
        .iter()
        .map(|i| WORDS[*i as usize].clone())
        .collect();

    let chk = checksum(&key);
    mnemonic.push(WORDS[chk as usize].clone());

    return mnemonic;
}

/// Converts a mnemonic word list into a key.
/// Returns an error if the mnemonic:
///   - has wrong length, or
///   - has an invalid checksum, or
///   - contains a word not from the word list
fn mnemonic_to_key(mnemonic: &Vec<String>) -> Result<[u8; KEY_LEN_BYTES], MnemonicError> {
    if mnemonic.len() != MNEMONIC_LEN_WORDS {
        return Err(MnemonicError::WrongMnemonicLen(mnemonic.len()));
    }

    let mut base11 = Vec::new();
    for word in mnemonic {
        match WORDS.iter().position(|w| w == word) {
            None => {
                return Err(MnemonicError::InvalidWordInMnemonic(word.clone()));
            }
            Some(pos) => base11.push(pos as u32),
        }
    }

    // convert to bytes, excluding the checksum word's base11 value
    let mut bytes = to_base8(&base11[..base11.len() - 1]);

    // We need to chop the last byte:
    // The short explanation - Since 256 is not divisible by 11, we have an extra 0x0 byte.
    // The longer explanation - When splitting the 256 bits to chunks of 11, we get 23 words and a left over of 3 bits.
    //   This left gets padded with another 8 bits to the create the 24th word.
    //   While converting back to byte array, our new 264 bits array is divisible by 8 but the last byte is just the padding.

    if bytes.len() != KEY_LEN_BYTES + 1 {
        // TODO can this happen?
        unreachable!("{} instead of {} bytes", bytes.len(), KEY_LEN_BYTES + 1);
    }

    if bytes[KEY_LEN_BYTES] != 0 {
        println!("bytes[KEY_LEN_BYTES] = {} != 0", bytes[KEY_LEN_BYTES]);
        return Err(MnemonicError::WrongChecksum);
    }

    bytes.pop();
    let bytes: [u8; KEY_LEN_BYTES] = bytes.as_slice().try_into().unwrap();

    if checksum(&bytes) != base11[base11.len() - 1] {
        return Err(MnemonicError::WrongChecksum);
    }

    return Ok(bytes);
}

fn load_mnemonic_file() -> Vec<String> {
    let mut wordlist = Vec::new();
    let f = File::open("./data/mnemonics_wordlist.txt").unwrap();

    for word in BufReader::new(f).lines() {
        if word.is_err() {
            continue;
        }
        wordlist.push(word.unwrap().clone());
    }

    if wordlist.len() != (1 << BITS_PER_WORD) {
        panic!(
            "wrong number of words in wordlist file: expected {}",
            1 << BITS_PER_WORD
        );
    }

    return wordlist;
}

fn checksum(data: &[u8]) -> u32 {
    let hash = Sha512Trunc256::digest(data);
    return to_base11(&hash[0..2])[0];
}

/// base 8 (u8) -> base 11 (u32)
// https://stackoverflow.com/a/50285590/356849
fn to_base11(base8_data: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut buf_bits = 0;

    for &x in base8_data {
        buf |= (x as u32) << buf_bits;
        buf_bits += 8;
        if buf_bits >= 11 {
            out.push(buf & 0x7ff); // 0x7ff is 2047, the max 11 bit number
            buf >>= 11;
            buf_bits -= 11;
        }
    }

    if buf_bits != 0 {
        out.push(buf & 0x7ff);
    }

    return out;
}

/// base 11 (u32) -> base 8 (u8)
/// May result in an extra 0x00 byte at the end.
// https://stackoverflow.com/a/50285590/356849
fn to_base8(base11_data: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut buf_bits = 0;

    for &x in base11_data {
        buf |= x << buf_bits;
        buf_bits += 11;
        while buf_bits >= 8 {
            out.push(buf as u8);
            buf >>= 8;
            buf_bits -= 8;
        }
    }

    if buf_bits != 0 {
        out.push(buf as u8);
    }

    return out;
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, RngCore};

    #[test]
    fn zero_vector() {
        assert_eq!(
            key_to_mnemonic([0; KEY_LEN_BYTES]),
            vec![
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
                "abandon", "abandon", "abandon", "invest",
            ]
        );
    }

    #[test]
    fn generate_and_recover() {
        let mut rng = thread_rng();
        let mut key = [0; KEY_LEN_BYTES];

        for _ in 0..1000 {
            rng.fill_bytes(&mut key);
            let mnemonic = key_to_mnemonic(key);
            assert_eq!(mnemonic.len(), MNEMONIC_LEN_WORDS);
            let recovered = mnemonic_to_key(&mnemonic).unwrap();
            assert_eq!(recovered.len(), KEY_LEN_BYTES);
            assert_eq!(recovered, key);
        }
    }

    #[test]
    fn wrong_mnemonic_length() {
        const BAD_LENGTHS: [usize; 4] = [0, MNEMONIC_LEN_WORDS - 1, MNEMONIC_LEN_WORDS + 1, 1000];

        for len in BAD_LENGTHS {
            let mnemonic = std::iter::repeat("abandon".to_owned()).take(len).collect();
            assert_eq!(
                mnemonic_to_key(&mnemonic),
                Err(MnemonicError::WrongMnemonicLen(len))
            );
        }
    }

    #[test]
    fn word_not_in_list() {
        let mut mnemonic = ["abandon"; MNEMONIC_LEN_WORDS - 2]
            .map(|s| s.to_owned())
            .to_vec();
        mnemonic.push("zzz".to_owned());
        mnemonic.push("invest".to_owned());

        assert_eq!(
            mnemonic_to_key(&mnemonic),
            Err(MnemonicError::InvalidWordInMnemonic("zzz".to_owned()))
        );
    }

    #[test]
    fn invalid_checksum() {
        let mut rng = thread_rng();
        let mut key = [0; KEY_LEN_BYTES];
        rng.fill_bytes(&mut key);

        let mut mnemonic = key_to_mnemonic(key);
        let real_checksum_word = mnemonic.last().unwrap().clone();

        for word in WORDS.iter() {
            if word == &real_checksum_word {
                continue;
            }

            *mnemonic.last_mut().unwrap() = word.clone();

            assert_eq!(
                mnemonic_to_key(&mnemonic),
                Err(MnemonicError::WrongChecksum)
            );
        }
    }

    #[test]
    fn base_conversion() {
        // zero vector
        let data = [0; 33];
        let base11 = to_base11(&data);
        let base8 = to_base8(&base11);
        assert_eq!(base8, data);

        // random tests
        let mut rng = thread_rng();
        let mut data = [0; 33];
        for _ in 0..1000 {
            rng.fill_bytes(&mut data);
            let base11 = to_base11(&data);
            let base8 = to_base8(&base11);
            assert_eq!(base8, data);
        }
    }
}
