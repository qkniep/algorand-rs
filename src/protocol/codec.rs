// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

pub fn encode(x: &impl Serialize) -> Vec<u8> {
    rmp_serde::to_vec(x).unwrap()
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice::<T>(bytes)
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Serialize)]
    struct TestStruct {
        #[serde(default, skip_serializing_if = "is_default")]
        pub a: u32,
        #[serde(default, skip_serializing_if = "is_default")]
        pub b: bool,
        #[serde(default, skip_serializing_if = "is_default")]
        pub c: Vec<u8>,
    }

    #[test]
    fn omit_empty() {
        let x = TestStruct {
            a: 0,
            b: false,
            c: Vec::new(),
        };
        let enc = encode(&x);
        println!("{:?}", enc);
        assert_eq!(enc.len(), 1);
    }
}
