// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use num::{
    bigint::{BigInt, Sign},
    rational::BigRational,
    ToPrimitive,
};
use statrs::distribution::{Binomial, DiscreteCDF};

use crate::crypto;

/// Runs the sortition function and returns the number of time the key was selected.
pub fn select(
    money: u64,
    total_money: u64,
    expected_size: f64,
    vrf_output: &crypto::CryptoHash,
) -> u64 {
    let p = expected_size / total_money as f64;
    let t = BigInt::from_bytes_be(Sign::Plus, &vrf_output.0);

    let max = BigInt::parse_bytes(
        b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        16,
    )
    .unwrap();

    let ratio = BigRational::new(t, max);
    let cratio = ratio.to_f64().unwrap();

    sortition_binomial_cdf_walk(money, p, cratio)
}

fn sortition_binomial_cdf_walk(n: u64, p: f64, ratio: f64) -> u64 {
    let bin = Binomial::new(p, n).unwrap();
    (0..n)
        .into_iter()
        .find(|&i| bin.cdf(i) >= ratio)
        .unwrap_or(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{thread_rng, RngCore};

    #[test]
    fn basic() {
        let n = 1000;
        let expected_size = 20;
        let my_money = 100;
        let total_money = 200;
        let mut rng = thread_rng();
        let mut hitcount = 0;

        for _ in 0..n {
            let mut vrf_output = crypto::CryptoHash([0; crypto::HASH_LEN]);
            rng.fill_bytes(&mut vrf_output.0);
            let selected = select(my_money, total_money, expected_size as f64, &vrf_output);
            hitcount += selected;
        }
        let expected = n * expected_size / 2;
        let d = if expected > hitcount {
            expected - hitcount
        } else {
            hitcount - expected
        };
        // within 2% good enough
        let max_d = expected / 50;
        assert!(
            d <= max_d,
            "wanted {} selections but got {}, {} > {}",
            expected,
            hitcount,
            d,
            max_d
        )
    }
}
