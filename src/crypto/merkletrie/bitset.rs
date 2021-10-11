// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Implementation of Bitset, a 256 bits bitmask storage.
//! The simplistic implementation is designed explicitly to reduce memory utilization to the minimum required.

/// A 256-bits bitmask storage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bitset {
    data: [u64; 4],
}

impl Bitset {
    /// Sets the given bit in the bitset.
    pub fn set_bit(&mut self, bit: u64) {
        self.data[bit as usize / 64] |= 1 << (bit & 63);
    }

    /// Clears the given bit in the bitset.
    pub fn clear_bit(&mut self, bit: u64) {
        // the &^ is the go and-not operator
        self.data[bit as usize / 64] &= !(1 << (bit & 63));
    }

    /// Tests the given bit in the bitset.
    pub fn bit(&self, bit: u64) -> bool {
        (self.data[bit as usize / 64] & (1 << (bit & 63))) != 0
    }

    /// Tests to see if all the bits in the bitset are set to zero.
    pub fn is_zero(&self) -> bool {
        self.data == [0; 4]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let mut a = Bitset::default();
        let mut b = Bitset::default();

        // set the bits in a different order, and see if we're ending with the same set.
        for i in (0..=255).step_by(2) {
            a.set_bit(i);
            b.set_bit((256 - i) % 256);
        }
        assert_eq!(a, b);

        for i in (0..=255).step_by(2) {
            assert_eq!(a.bit(i), true);
            assert_eq!(b.bit(i + 1), false);
        }

        // clear the bits at different order, and testing that the bits were cleared correctly.
        for i in (0..=255).step_by(32) {
            a.clear_bit(i);
            b.clear_bit((256 - i) % 256);
        }
        assert_eq!(a, b);

        for i in (0..=255).step_by(32) {
            assert_eq!(a.bit(i), false);
        }

        // clear all bits (some would get cleared more than once)
        for i in (0..=255).step_by(2) {
            a.clear_bit(i);
        }

        // check that the bitset is zero.
        assert!(a.is_zero());
    }

    /// Tests that only one bit is being set when we call `Bitset::set_bit()`.
    #[test]
    fn set_one_bit() {
        for i in 0..=255 {
            let mut a = Bitset::default();
            a.set_bit(i);
            let ones_count = a.data[0].count_ones()
                + a.data[1].count_ones()
                + a.data[2].count_ones()
                + a.data[3].count_ones();
            assert_eq!(ones_count, 1);
        }
    }
}
