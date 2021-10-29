// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fmt;
use std::ops::Add;

use serde::{Deserialize, Serialize};

use crate::config;
use crate::crypto;

/// A number of rounds.
pub type RoundInterval = u64;

/// Main unit of currency. It is wrapped in a struct to nudge
/// developers to use an overflow-checking library for any arithmetic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MicroAlgos(pub u64);

/// A protocol round index.
#[derive(
    Clone, Copy, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Round(pub u64);

impl MicroAlgos {
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub fn to_u64(&self) -> u64 {
        self.0
    }

    /// The number of reward units in some number of algos.
    // TODO better doc comment
    pub fn reward_units(&self, proto: &config::ConsensusParams) -> u64 {
        self.0 / proto.reward_unit
    }

    // We generate our own encoders and decoders for MicroAlgos
    // because we want it to appear as an integer, even though
    // we represent it as a single-element struct.
    //msgp:ignore MicroAlgos
    // TODO is this necessary in Rust implementation?
    // TODO if yes: implement the codec methods from https://github.com/algorand/go-algorand/blob/master/data/basics/units.go
}

impl fmt::Display for MicroAlgos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "μA {}", self.0)
    }
}

impl Add for MicroAlgos {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl fmt::Display for Round {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Round {
    /// Maps a round to the identifier for which ephemeral key should be used for that round.
    /// key_dilution specifies the number of keys in the bottom-level of the two-level key structure.
    pub fn ots_id(&self, key_dilution: u64) -> crypto::OTSIdentifier {
        crypto::OTSIdentifier {
            batch: self.0 / key_dilution,
            offset: self.0 % key_dilution,
        }
    }

    /// Subtracts r rounds.
    /// Does not wrap around past zero, instead returns 0 on underflow.
    fn sub_capped(&self, r: Self) -> Self {
        match r {
            r if r.0 < self.0 => Self(self.0 - r.0),
            _ => Self(0),
        }
    }

    /// Rounds up round number to the next multiple of r.
    fn round_up_to_multiple_of(&self, r: Self) -> Self {
        Self((self.0 + r.0 - 1) / r.0 * r.0)
    }
}

impl Add for Round {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subtraction() {
        let a = Round(1);
        let b = Round(2);
        assert_eq!(a.sub_capped(b), Round(0));
        assert_eq!(a.sub_capped(a), Round(0));
        assert_eq!(b.sub_capped(a), Round(1));
    }

    #[test]
    fn rounding() {
        let r = Round(24);

        for n in 1..100 {
            let round_n = Round(n);
            let mul = r.round_up_to_multiple_of(round_n);
            assert!(r <= mul);
            assert_eq!(mul.0 % n, 0);
            if round_n < r {
                let prev = mul.0 - n;
                assert!(prev < r.0);
            }
        }
    }
}
