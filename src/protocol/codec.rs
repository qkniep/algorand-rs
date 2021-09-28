// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use rmp_serde::Serializer;
use serde::{Deserialize, Serialize};

pub fn encode(x: &impl Serialize) -> Vec<u8> {
    let mut enc = Vec::new();
    x.serialize(&mut Serializer::new(&mut enc)).unwrap();
    enc
}

pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice::<T>(bytes)
}

/*
#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Serialize)]
    struct TestStruct {
        pub a: u32,
        pub b: bool,
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
*/
