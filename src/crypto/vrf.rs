// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Implementation of ECVRF-ED25519-SHA512-Elligator2 (IETF Draft 3).
//! For specification see: https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03

use std::convert::TryInto;

use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use thiserror::Error;

/// A single byte string identifying ECVRF-ED25519-SHA512-Elligator2.
const SUITE_STRING: [u8; 1] = [0x04];

/// A single byte string identifying ECVRF-ED25519-SHA512-Elligator2.
const COFACTOR: u32 = 8;

/// Different errors that can be raised when proving/verifying VRFs.
#[derive(Debug, Error)]
pub enum VrfError {
    /// The `hash_to_point()` function could not find a valid point.
    #[error("Hash to point function could not find a valid point")]
    HashToPointError,

    /// The proof length is invalid.
    #[error("The proof length is invalid")]
    InvalidPiLength,

    /// The proof is invalid.
    #[error("The proof is invalid")]
    InvalidProof,

    /// Unknown error.
    #[error("Unknown error")]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfKeypair {
    private: [u8; 32],
    public: VrfPublicKey,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfPublicKey([u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfProof([u8; 80]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput([u8; 64]);

impl VrfKeypair {
    /// Generates a private/public keypair from a secret seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SecretKey::from_bytes(&seed).unwrap();
        let pk: PublicKey = (&sk).into();
        Self {
            private: seed,
            public: VrfPublicKey(pk.to_bytes()),
        }
    }

    /// Generates a proof for a given message using this secret key, as specified in:
    /// https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03 (section 5.1).
    pub fn prove_bytes(&self, bytes: &[u8]) -> Result<VrfProof, ()> {
        // Step 1: Derive public key. (not necessary, already available as self.public)
        // Step 2: H = ECVRF_hash_to_curve(Y, alpha_string)
        let hash_point = hash_to_curve(&self.public, bytes).unwrap();

        // Step 3: h_string = point_to_string(H)
        let h_str = hash_point.compress().to_bytes();

        // Step 4: Gamma = x*H
        let xsk: ExpandedSecretKey = (&SecretKey::from_bytes(&self.private).unwrap()).into();
        let x = Scalar::from_bits(xsk.to_bytes()[..32].try_into().unwrap());
        let gamma = x * hash_point;

        // Step 5: k = ECVRF_nonce_generation(SK, h_string)
        let k = gen_nonce(&self.private, &h_str);

        // Step 6: c = ECVRF_hash_points(H, Gamma, k*B, k*H)
        let b = constants::ED25519_BASEPOINT_POINT;
        let c = hash_points(hash_point, gamma, k * b, k * hash_point);

        // Step 7: s = (k + c*x) mod q
        let s = k + c * x;

        // Step 8: pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
        let gamma_str = &gamma.compress().to_bytes()[..];
        let pi = &[gamma_str, &c.as_bytes()[..16], &s.as_bytes()[..]].concat();
        let pi_fixed: [u8; 80] = pi.as_slice().try_into().unwrap();

        // Step 9: Output pi_string.
        let proof = VrfProof(pi_fixed);
        return Ok(proof);
    }

    /// Gets a copy of the public key.
    pub fn public(&self) -> VrfPublicKey {
        self.public.clone()
    }
}

impl VrfPublicKey {
    /// Validates a proof for a given message against this public key, as specified in:
    /// https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03 (section 5.3).
    pub fn verify_bytes(&self, proof: VrfProof, bytes: &[u8]) -> Result<VrfOutput, VrfError> {
        let d = proof.decode();
        if d.is_none() {
            return Err(VrfError::InvalidProof);
        }

        let (gamma, c, s) = d.unwrap();
        let h = hash_to_curve(self, bytes)?;

        let u = s * constants::ED25519_BASEPOINT_POINT - c * self.to_point();
        let v = s * h - c * gamma;
        let c_calculated = hash_points(h, gamma, u, v);

        if c_calculated == c {
            return Ok(proof.to_output());
        } else {
            return Err(VrfError::InvalidProof);
        }
    }

    /// Converts the public key, which is a compressed point representation, to the curve point.
    /// Panics if the public key does not correspond to a valid curve point.
    fn to_point(&self) -> EdwardsPoint {
        CompressedEdwardsY::from_slice(&self.0)
            .decompress()
            .unwrap()
    }
}

impl VrfProof {
    /// Decodes the proof into its components:
    ///   * gamma - EC point
    ///   * c     - 16-bit scalar value
    ///   * s     - 32-bit scalar value
    /// Returns None if the encoding was invalid in any way.
    fn decode(&self) -> Option<(EdwardsPoint, Scalar, Scalar)> {
        let gamma = CompressedEdwardsY::from_slice(&self.0[..32]).decompress()?;
        let c_str = [&self.0[32..48], &[0; 16][..]].concat().try_into().unwrap();
        let c = Scalar::from_canonical_bytes(c_str)?;
        let s_str = self.0[48..80].try_into().unwrap();
        let s = Scalar::from_canonical_bytes(s_str)?;
        return Some((gamma, c, s));
    }

    ///
    /// All checks should have already been done; panics if inputs are invalid.
    fn to_output(&self) -> VrfOutput {
        let (gamma, _, _) = self.decode().unwrap();
        let cg = Scalar::from(COFACTOR) * gamma;
        let s = [&SUITE_STRING, &[0x03], &cg.compress().as_bytes()[..]].concat();
        let beta = Sha512::digest(&s).as_slice().try_into().unwrap();
        return VrfOutput(beta);
    }
}

impl AsRef<[u8]> for VrfProof {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

/// Dumb digest which just truncates everything after 512 bits.
/// It's meant to be used as a no-op: 512 bits in, same 512 bits out.
/// Needed only for the dirty hack below.
#[derive(Default)]
struct TruncHasher(Vec<u8>);

impl Digest for TruncHasher {
    type OutputSize = generic_array::typenum::U64;

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.extend_from_slice(&data.as_ref());
    }

    fn finalize(self) -> GenericArray<u8, Self::OutputSize> {
        *GenericArray::from_slice(&self.0[..=63])
    }

    fn chain(self, _: impl AsRef<[u8]>) -> Self {
        unimplemented!()
    }
    fn finalize_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
    fn reset(&mut self) {
        unimplemented!()
    }
    fn output_size() -> usize {
        unimplemented!()
    }
    fn digest(_: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        unimplemented!()
    }
}

/// Cryptographically hash byte string to ed25519 curve point, as specified in:
/// https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03 (section 5.4.1.2).
fn hash_to_curve(pk: &VrfPublicKey, bytes: &[u8]) -> Result<EdwardsPoint, VrfError> {
    let s = [&SUITE_STRING, &[0x01], &pk.0[..], &bytes[..]].concat();

    // Hack to avoid forking curve25519_dalek crate because it implements a newer IETF draft:
    // Hash in here and tell `hash_from_bytes` function to use TruncHasher.
    let mut h = Sha512::digest(&s);
    h[31] &= 0x7F;

    Ok(EdwardsPoint::hash_from_bytes::<TruncHasher>(&h))
}

/// Deterministically generates nonce, as specified in:
/// https://datatracker.ietf.org/doc/html/rfc8032 (section 5.1.6, steps 1-2).
fn gen_nonce(sk: &[u8; 32], data: &[u8]) -> Scalar {
    let h = Sha512::digest(sk);
    let trunc_h: [u8; 32] = h[32..].try_into().unwrap();
    let k_ga = Sha512::digest(&[&trunc_h, data].concat());
    let k = k_ga.as_slice().try_into().unwrap();
    return Scalar::from_bytes_mod_order_wide(k);
}

/// Hash points into a scalar, as specified in:
/// https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03 (section 5.4.3).
fn hash_points(a: EdwardsPoint, b: EdwardsPoint, c: EdwardsPoint, d: EdwardsPoint) -> Scalar {
    let a_str = &a.compress().to_bytes()[..];
    let b_str = &b.compress().to_bytes()[..];
    let c_str = &c.compress().to_bytes()[..];
    let d_str = &d.compress().to_bytes()[..];
    let s = [&SUITE_STRING, &[0x02], a_str, b_str, c_str, d_str].concat();
    let h = Sha512::digest(&s);
    let mut out_bytes = [0; 32];
    out_bytes[..16].copy_from_slice(&h[..16]);
    return Scalar::from_bytes_mod_order(out_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    use data_encoding::HEXLOWER;

    /// ECVRF-ED25519-SHA512-Elligator2 test vectors from: https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-03
    #[test]
    fn vrf_test_vectors() {
        test_vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", //sk
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", //pk
            "", // alpha
            "1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7", // hash
            "b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900", // pi
            "5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc",                                 // beta
        );

        test_vector("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", //sk
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", //pk
            "72", // alpha
            "86725262c971bf064168bca2a87f593d425a49835bd52beb9f52ea59352d80fa", // hash
            "ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e6ae1111a55717e895fd15f99f07", // pi
            "94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8",                                 // beta
        );

        test_vector("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", //sk
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", //pk
            "af82", // alpha
            "9d8663faeb6ab14a239bfc652648b34f783c2e99f758c0e1b6f4f863f9419b56", // hash
            "dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff78ef493f820055b561ece45e1009", // pi
            "2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319dde9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded",                                 // beta
        );
    }

    /// Helper function for checking a single test vector.
    /// All arguments need to be passed as hex strings.
    fn test_vector(
        sk_hex: &str,
        pk_hex: &str,
        alpha_hex: &str,
        hash_hex: &str,
        pi_hex: &str,
        beta_hex: &str,
    ) {
        // Decode hex
        let seed: [u8; 32] = hex_decode(sk_hex).as_slice().try_into().unwrap();
        let pk = VrfPublicKey(hex_decode(pk_hex).as_slice().try_into().unwrap());
        let alpha = &hex_decode(alpha_hex);
        let hash: [u8; 32] = hex_decode(hash_hex).as_slice().try_into().unwrap();
        let pi = VrfProof(hex_decode(pi_hex).as_slice().try_into().unwrap());
        let beta = VrfOutput(hex_decode(beta_hex).as_slice().try_into().unwrap());

        let kp = VrfKeypair::from_seed(seed);
        assert_eq!(kp.public(), pk);

        let hash_calculated = hash_to_curve(&kp.public, alpha).unwrap();
        assert_eq!(hash_calculated.compress().to_bytes(), hash);

        let pi_calculated = kp.prove_bytes(alpha).unwrap();
        assert_eq!(pi_calculated, pi);

        let beta_calculated = pk.verify_bytes(pi, alpha).unwrap();
        assert_eq!(beta_calculated, beta);
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        HEXLOWER.decode(hex.as_bytes()).unwrap()
    }
}
