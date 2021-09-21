// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

// TODO implement benchmarks

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfPrivKey([u8; 64]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfPubKey([u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof([u8; 80]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput([u8; 64]);

pub fn keypair_from_seed(seed: [u8; 32]) -> (VrfPubKey, VrfPrivKey) {
    unimplemented!();
}

impl VrfPrivKey {
    fn prove_bytes(&self, bytes: &[u8]) -> Result<VrfProof, ()> {
        unimplemented!();
    }
}

impl VrfPubKey {
    fn verify_bytes(&self, pi: &[u8], alpha: &[u8]) -> Result<VrfOutput, ()> {
        unimplemented!();
    }
}

impl AsRef<[u8]> for VrfProof {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    use data_encoding::HEXLOWER;

    /// ECVRF-ED25519-SHA512-Elligator2 test vectors from: https://www.ietf.org/id/draft-irtf-cfrg-vrf-03.txt appendix A.4
    #[test]
    fn vrf_test_vectors() {
        test_vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", //sk
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", //pk
            "", // alpha
            "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // pi
            "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",                                 // beta
        );

        test_vector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", //sk
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", //pk
            "72", // alpha
            "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
            "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",                                 // beta
        );
    }

    /// Helper function for checking a single test vector.
    /// All arguments need to be passed as hex strings.
    fn test_vector(sk_hex: &str, pk_hex: &str, alpha_hex: &str, pi_hex: &str, beta_hex: &str) {
        // our "secret keys" are 64 bytes: the spec's 32-byte "secret keys" (which we call the "seed") followed by the 32-byte precomputed public key
        // so the 32-byte "SK" in the test vectors is not directly decoded into a VrfPrivkey, it instead has to go through VrfKeypairFromSeed()
        let seed = [0u8; 32];

        // Decode hex
        let seed = hex_decode(sk_hex).as_slice().try_into().unwrap();
        let pk = VrfPubKey(hex_decode(pk_hex).as_slice().try_into().unwrap());
        let alpha = &hex_decode(alpha_hex);
        let pi = VrfProof(hex_decode(pi_hex).as_slice().try_into().unwrap());
        let beta = VrfOutput(hex_decode(beta_hex).as_slice().try_into().unwrap());

        let (pk_calculated, sk) = keypair_from_seed(seed);
        assert_eq!(pk_calculated, pk);

        let pi_calculated = sk.prove_bytes(alpha).unwrap();
        assert_eq!(pi_calculated, pi);

        let beta_calculated = pk.verify_bytes(&pi.0[..], alpha).unwrap();
        assert_eq!(beta_calculated, beta);
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        HEXLOWER.decode(hex.as_bytes()).unwrap()
    }
}
