// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryInto;

use ed25519::Signature;
use ed25519_dalek::{Keypair, PublicKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512Trunc256};
use thiserror::Error;

use crate::crypto::batch_verifier::BatchVerifier;

const MAX_MULTISIG: u8 = 255;

// TODO implement and use Hashable trait

#[derive(Debug, PartialEq, Eq)]
struct MultisigAddr([u8; 32]);

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSubsig {
    pub key: PublicKey,
    pub sig: Option<Signature>,
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSignature {
    pub version: u8,
    pub threshold: u8,
    pub subsigs: Vec<MultisigSubsig>,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum MultisigError {
    #[error("unknown version {0}")]
    UnknownVersion(u8),
    #[error("invalid threshold")]
    InvalidThreshold,
    #[error("at least one signature was invalid")]
    InvalidSignature,
    #[error("invalid address")]
    InvalidAddress,
    #[error("invalid number of signatures provided")]
    InvalidNumberOfSignatures,
    #[error("key does not exist")]
    KeyNotExists,
    #[error("thresholds don't match: {0} != {1}")]
    ThresholdsDontMatch(u8, u8),
    #[error("versions don't match: {0} != {1}")]
    VersionsDontMatch(u8, u8),
    #[error("public key lists don't match")]
    KeysDontMatch,
    #[error("invalid duplicates")]
    InvalidDuplicates,
}

impl MultisigAddr {
    fn from_pks(version: u8, threshold: u8, pks: &[PublicKey]) -> Result<Self, MultisigError> {
        if version != 1 {
            return Err(MultisigError::UnknownVersion(version));
        }

        if threshold == 0 || pks.is_empty() || threshold as usize > pks.len() {
            return Err(MultisigError::InvalidThreshold);
        }

        let mut buf = b"MultisigAddr".to_vec();
        buf.push(version);
        buf.push(threshold);

        for pk in pks {
            buf.extend(pk.as_bytes());
        }

        Ok(Self(Sha512Trunc256::digest(&buf).try_into().unwrap()))
    }

    // MultisigAddrGenWithSubsigs is similar to MultisigAddrGen
    // except the input is []Subsig rather than []PublicKey
    fn from_subsigs(
        version: u8,
        threshold: u8,
        subsigs: &[MultisigSubsig],
    ) -> Result<Self, MultisigError> {
        let pks: Vec<PublicKey> = subsigs.iter().map(|s| s.key).collect();
        Self::from_pks(version, threshold, &pks)
    }

    /// Has to be called for each signing party individually.
    fn sign(
        &self,
        msg: &[u8],
        version: u8,
        threshold: u8,
        pks: &[PublicKey],
        kp: &Keypair,
    ) -> Result<MultisigSignature, MultisigError> {
        if version != 1 {
            return Err(MultisigError::UnknownVersion(version));
        }

        // check the address matches the keys
        let addr = Self::from_pks(version, threshold, pks)?;

        if *self != addr {
            return Err(MultisigError::InvalidAddress);
        }

        // setup parameters
        let mut sig = MultisigSignature {
            version,
            threshold,
            subsigs: Vec::with_capacity(pks.len()),
        };

        // check if own public key is in the pk list
        if !pks.contains(&kp.public) {
            return Err(MultisigError::KeyNotExists);
        }

        // form the multisig
        for (i, &pk) in pks.iter().enumerate() {
            sig.subsigs.push(MultisigSubsig { key: pk, sig: None });
            if kp.public == pk {
                sig.subsigs[i].sig = Some(kp.sign(msg));
            }
        }

        Ok(sig)
    }
}

impl MultisigSignature {
    /// Combines multiple `MultisigSignature` into one
    fn assemble(unisig: &[Self]) -> Result<Self, MultisigError> {
        if unisig.len() < 2 {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // check if all unisig match
        for i in 1..unisig.len() {
            if unisig[0].threshold != unisig[i].threshold {
                return Err(MultisigError::ThresholdsDontMatch(
                    unisig[0].threshold,
                    unisig[i].threshold,
                ));
            } else if unisig[0].version != unisig[i].version {
                return Err(MultisigError::VersionsDontMatch(
                    unisig[0].version,
                    unisig[i].version,
                ));
            } else if unisig[0].subsigs.len() != unisig[i].subsigs.len() {
                return Err(MultisigError::InvalidNumberOfSignatures);
            }
            for j in 0..unisig[0].subsigs.len() {
                if unisig[0].subsigs[j].key != unisig[i].subsigs[j].key {
                    return Err(MultisigError::KeysDontMatch);
                }
            }
        }

        // make the assembled signature
        let mut msig = MultisigSignature {
            version: unisig[0].version,
            threshold: unisig[0].threshold,
            subsigs: Vec::with_capacity(unisig[0].subsigs.len()),
        };

        for i in 0..unisig[0].subsigs.len() {
            msig.subsigs.push(MultisigSubsig {
                key: unisig[0].subsigs[i].key,
                sig: None,
            });
        }

        // TODO what happens if unisig contains multiple copies of the same sig?
        // TODO add this as test case!
        for i in 0..unisig.len() {
            for j in 0..unisig[0].subsigs.len() {
                if let Some(s) = unisig[i].subsigs[j].sig {
                    msig.subsigs[j].sig = Some(s);
                }
            }
        }

        Ok(msig)
    }

    fn verify(&self, msg: &[u8], addr: &MultisigAddr) -> Result<bool, MultisigError> {
        let mut batch_verifier = BatchVerifier::default();

        if !self.batch_verify(msg, addr, &mut batch_verifier)? {
            Ok(false)
        } else if batch_verifier.num_sigs_enqued() == 0 {
            Ok(true)
        } else {
            Ok(batch_verifier.verify().is_ok())
        }
    }

    // MultisigBatchVerify verifies an assembled MultisigSig.
    // it is the caller responsibility to call batchVerifier.verify()
    fn batch_verify(
        &self,
        msg: &[u8],
        addr: &MultisigAddr,
        batch_verifier: &mut BatchVerifier,
    ) -> Result<bool, MultisigError> {
        // short circuit: if msig doesn't have subsigs or if Subsigs are empty
        // then terminate (the upper layer should now verify the unisig)
        if self.subsigs.is_empty() || self.subsigs[0] == MultisigSubsig::default() {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // check the address is correct
        let addrnew = MultisigAddr::from_subsigs(self.version, self.threshold, &self.subsigs)?;
        if *addr != addrnew {
            return Err(MultisigError::InvalidAddress);
        }

        // check that we don't have too many multisig subsigs
        if self.subsigs.len() > MAX_MULTISIG as usize {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // check that we don't have too few multisig subsigs
        if self.subsigs.len() < self.threshold as usize {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // checks the number of non-blank signatures is no less than threshold
        let non_empty = self.subsigs.iter().filter(|s| s.sig.is_some()).count();
        if non_empty < self.threshold as usize {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // checks individual signature verifies
        let mut verified = 0;
        for sub_sig in &self.subsigs {
            if let Some(s) = sub_sig.sig {
                batch_verifier.enque_sig(sub_sig.key, msg, s);
                verified += 1;
            }
        }

        // sanity check. if we get here then every non-blank subsig should have
        // been verified successfully, and we should have had enough of them
        if verified < self.threshold {
            Err(MultisigError::InvalidNumberOfSignatures)
        } else {
            Ok(true)
        }
    }

    /// Adds unisigs to an existing msig.
    fn add_sigs(&mut self, unisigs: Vec<Self>) -> Result<(), MultisigError> {
        if unisigs.is_empty() {
            return Err(MultisigError::InvalidNumberOfSignatures);
        }

        // check if all unisig match
        // TODO write function for this match check!
        for unisig in &unisigs {
            if self.threshold != unisig.threshold {
                return Err(MultisigError::ThresholdsDontMatch(
                    self.threshold,
                    unisig.threshold,
                ));
            } else if self.version != unisig.version {
                return Err(MultisigError::VersionsDontMatch(
                    self.version,
                    unisig.version,
                ));
            } else if self.subsigs.len() != unisig.subsigs.len() {
                return Err(MultisigError::KeysDontMatch);
            }

            for i in 0..unisigs[0].subsigs.len() {
                if self.subsigs[i].key != unisig.subsigs[i].key {
                    return Err(MultisigError::KeysDontMatch);
                }
            }
        }

        // update the msig
        for usig in unisigs {
            for (i, mut subsig) in self.subsigs.iter_mut().enumerate() {
                if usig.subsigs[i].sig.is_some() {
                    if subsig.sig.is_none() {
                        // add the signature
                        subsig.sig = usig.subsigs[i].sig;
                    } else if subsig.sig != usig.subsigs[i].sig {
                        // invalid duplicates
                        return Err(MultisigError::InvalidDuplicates);
                    }
                }
            }
        }

        Ok(())
    }

    // MultisigMerge merges two Multisigs msig1 and msig2 into msigt
    fn merge(&self, other: &MultisigSignature) -> Result<Self, MultisigError> {
        // TODO write function for this match check!
        //      like this: self.matches(other)?;
        // check if all parameters match
        if self.threshold != other.threshold
            || self.version != other.version
            || self.subsigs.len() != other.subsigs.len()
        {
            return Err(MultisigError::InvalidThreshold);
        }

        for i in 0..self.subsigs.len() {
            if self.subsigs[i].key != other.subsigs[i].key {
                return Err(MultisigError::KeysDontMatch);
            }
        }
        // update msigt
        let mut msig = MultisigSignature {
            version: self.version,
            threshold: self.threshold,
            subsigs: Vec::with_capacity(self.subsigs.len()),
        };

        for i in 0..self.subsigs.len() {
            msig.subsigs.push(MultisigSubsig {
                key: self.subsigs[i].key,
                sig: None,
            });

            if self.subsigs[i].sig.is_none() {
                if other.subsigs[i].sig.is_some() {
                    // update signature with msig2's signature
                    msig.subsigs[i].sig = other.subsigs[i].sig;
                }
            } else if other.subsigs[i].sig.is_none() || // msig2's sig is empty
                other.subsigs[i].sig == self.subsigs[i].sig
            {
                // valid duplicates
                // update signature with msig1's signature
                msig.subsigs[i].sig = self.subsigs[i].sig;
            } else {
                // invalid duplicates
                return Err(MultisigError::InvalidDuplicates);
            }
        }

        Ok(msig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{SecretKey, SECRET_KEY_LENGTH};
    use rand::{thread_rng, RngCore};

    use crate::crypto::batch_verifier::BatchVerError;

    #[test]
    fn address_generation() {
        let version = 1;
        let threshold = 3;

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::with_capacity(4);

        for _ in 0..4 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
        }

        let mut pks = vec![kps[0].public, kps[1].public];

        // keys < threshold
        // Should detect invalid threshold.
        let result = MultisigAddr::from_pks(version, threshold, &pks);
        assert_eq!(result, Err(MultisigError::InvalidThreshold));

        // keys == threshold
        pks.push(kps[2].public);
        let result = MultisigAddr::from_pks(version, threshold, &pks);
        assert_eq!(result.is_ok(), true);

        // keys > threshold
        pks.push(kps[3].public);
        let result = MultisigAddr::from_pks(version, threshold, &pks);
        assert_eq!(result.is_ok(), true);
    }

    // tests that generated addresses are compatible with go-algorand
    #[test]
    fn address_test_vector() {
        let version = 1;
        let threshold = 2;

        let mut kps = Vec::with_capacity(3);
        let mut pks = Vec::with_capacity(3);

        for i in 0..3 {
            let seed = [i; SECRET_KEY_LENGTH];
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        assert_eq!(
            addr.0,
            [
                215, 156, 40, 176, 255, 146, 124, 48, 105, 103, 167, 143, 244, 248, 78, 177, 30,
                135, 54, 239, 14, 170, 78, 81, 138, 24, 124, 68, 224, 121, 67, 203
            ]
        );
    }

    // this test generates a set of 4 public keys for a threshold of 3
    // signs with 3 keys to get 3 signatures
    // assembles 3 signatures, verify the msig
    #[test]
    fn multisig() {
        let version = 1;
        let threshold = 3;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::with_capacity(5);
        let mut pks = Vec::with_capacity(4);

        for _ in 0..5 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
        }

        // addr = hash (...|pk0|pk1|pk2|pk3), pk4 is not included
        pks.push(kps[0].public);
        pks.push(kps[1].public);
        pks.push(kps[2].public);
        pks.push(kps[3].public);
        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();

        // invalid version
        let result = addr.sign(tx, version + 1, threshold, &pks, &kps[0]);
        assert_eq!(result.is_err(), true);

        // invalid secret key
        let result = addr.sign(tx, version, threshold, &pks, &kps[4]);
        assert_eq!(result, Err(MultisigError::KeyNotExists));

        // single signature (3 required)
        let sigs = vec![addr.sign(tx, version, threshold, &pks, &kps[3]).unwrap()];
        let result = MultisigSignature::assemble(&sigs);
        assert_eq!(result, Err(MultisigError::InvalidNumberOfSignatures));

        // assemble 3 signatures
        let mut sigs = Vec::new();
        for i in 0..3 {
            sigs.push(addr.sign(tx, version, threshold, &pks, &kps[i]).unwrap());
        }
        let msig = MultisigSignature::assemble(&sigs).unwrap();
        assert_eq!(msig.verify(tx, &addr).unwrap(), true);

        // batch verification
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(msig.batch_verify(tx, &addr, &mut bv), Ok(true));
        assert_eq!(bv.verify(), Ok(()));
    }

    #[test]
    fn empty_multisig() {
        let version = 1;
        let threshold = 1;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        let mut pks = Vec::new();

        rng.fill_bytes(&mut seed);
        let sk = SecretKey::from_bytes(&seed).unwrap();
        pks.push((&sk).into());

        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let empty_sig = MultisigSignature {
            version,
            threshold,
            subsigs: Vec::new(),
        };
        assert_eq!(
            empty_sig.verify(tx, &addr),
            Err(MultisigError::InvalidNumberOfSignatures)
        );

        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            empty_sig.batch_verify(tx, &addr, &mut bv),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
    }

    // test multisig merge functions
    // 1. assembles 2 signatures, adds a 3rd one to form msig1
    // 2. verifies msig1
    // 3. assembles 4th and 5th to get msig2
    // 4. merge msig1 and msig2
    // 5. verify the merged one
    #[test]
    fn add_and_merge() {
        let version = 1;
        let threshold = 3;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0u8; SECRET_KEY_LENGTH];

        let mut kps = Vec::with_capacity(5);
        let mut pks = Vec::with_capacity(5);

        for _ in 0..5 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        // addr = hash (... |pk0|pk1|pk2|pk3|pk4)
        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();

        // msig1 = {sig0,sig1}
        let mut sigs = Vec::new();
        sigs.push(addr.sign(tx, version, threshold, &pks, &kps[0]).unwrap());
        sigs.push(addr.sign(tx, version, threshold, &pks, &kps[1]).unwrap());
        let mut msig1 = MultisigSignature::assemble(&sigs).unwrap();
        // add sig3 to msig and then verify
        let sigs = vec![addr.sign(tx, version, threshold, &pks, &kps[2]).unwrap()];
        msig1.add_sigs(sigs).unwrap();
        assert_eq!(msig1.verify(tx, &addr), Ok(true));

        // msig2 = {sig3, sig4}
        let mut sigs = Vec::new();
        sigs.push(addr.sign(tx, version, threshold, &pks, &kps[3]).unwrap());
        sigs.push(addr.sign(tx, version, threshold, &pks, &kps[4]).unwrap());
        let mut msig2 = MultisigSignature::assemble(&sigs).unwrap();
        // merge two msigs and then verify
        let msig = msig1.merge(&msig2).unwrap();
        assert_eq!(msig.verify(tx, &addr), Ok(true));

        // create a valid duplicate on purpose
        // msig1 = {sig0, sig1, sig2}
        // msig2 = {sig2, sig3, sig4}
        // then verify the merged signature
        let sigs = vec![addr.sign(tx, version, threshold, &pks, &kps[2]).unwrap()];
        msig2.add_sigs(sigs).unwrap();
        let msig = msig1.merge(&msig2).unwrap();
        assert_eq!(msig.verify(tx, &addr), Ok(true));
    }

    #[test]
    fn incorrect_address() {
        let version = 1;
        let threshold = 1;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];

        rng.fill_bytes(&mut seed);
        let sk = SecretKey::from_bytes(&seed).unwrap();
        let pks = vec![(&sk).into()];
        let kp = Keypair {
            secret: sk,
            public: pks[0],
        };

        let mut addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let msig = addr.sign(tx, version, threshold, &pks, &kp).unwrap();
        addr.0[0] = addr.0[0] + 1;
        assert_eq!(msig.verify(tx, &addr), Err(MultisigError::InvalidAddress));
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            msig.batch_verify(tx, &addr, &mut bv),
            Err(MultisigError::InvalidAddress)
        );
    }

    #[test]
    fn more_than_max_sigs() {
        let version = 1;
        let threshold = 1;
        let tx = b"text: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::new();
        let mut pks = Vec::new();

        for _ in 0..MAX_MULTISIG as usize + 1 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            let kp = Keypair { secret, public };
            kps.push(kp);
            pks.push(public);
        }

        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..MAX_MULTISIG as usize + 1 {
            sigs.push(addr.sign(tx, version, threshold, &pks, &kps[i]).unwrap());
        }

        let msig = MultisigSignature::assemble(&sigs).unwrap();
        assert_eq!(
            msig.verify(tx, &addr),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            msig.batch_verify(tx, &addr, &mut bv),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
    }

    #[test]
    fn one_sig_is_empty() {
        let multisig_len = 6;
        let version = 1;
        let threshold = multisig_len as u8;
        let tx = b"text: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::new();
        let mut pks = Vec::new();

        for _ in 0..multisig_len {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..multisig_len {
            sigs.push(addr.sign(tx, version, threshold, &pks, &kps[i]).unwrap());
        }

        let mut msig = MultisigSignature::assemble(&sigs).unwrap();
        msig.subsigs[0].sig = None;
        assert_eq!(
            msig.verify(tx, &addr),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            msig.batch_verify(tx, &addr, &mut bv),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
    }

    // in this test we want to test what happen if one of the signatures are not valid.
    // we create case where are enoguht valid signatures (that pass the thrashold). but since one is false. everything fails.
    #[test]
    fn one_sig_is_invalid() {
        let multisig_len = 6;
        let version = 1;
        let threshold = 3;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::new();
        let mut pks = Vec::new();

        for _ in 0..multisig_len {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..multisig_len {
            sigs.push(addr.sign(tx, version, threshold, &pks, &kps[i]).unwrap());
        }

        // break one signature
        let mut sig_bytes = sigs[1].subsigs[1].sig.unwrap().to_bytes();
        sig_bytes[5] += 1;
        sigs[1].subsigs[1].sig = Some(Signature::new(sig_bytes));

        let msig = MultisigSignature::assemble(&sigs).unwrap();
        assert_eq!(msig.verify(tx, &addr), Ok(false));
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(msig.batch_verify(tx, &addr, &mut bv), Ok(true));
        assert_eq!(bv.verify(), Err(BatchVerError::VerificationFailed));
    }

    #[test]
    fn less_than_threshold() {
        let version = 1;
        let threshold = 3;
        let tx = b"test: txid 1000";

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::new();
        let mut pks = Vec::new();

        for _ in 0..4 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        // addr  = hash (... |pk0|pk1|pk2|pk3)
        let addr = MultisigAddr::from_pks(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();
        for i in 0..3 {
            sigs.push(addr.sign(tx, version, threshold, &pks, &kps[i]).unwrap());
        }

        let mut msig = MultisigSignature::assemble(&sigs).unwrap();
        msig.subsigs[1].sig = None;
        assert_eq!(
            msig.verify(tx, &addr),
            Err(MultisigError::InvalidNumberOfSignatures)
        );

        let mut msig = MultisigSignature::assemble(&sigs).unwrap();
        msig.subsigs.pop();
        assert_eq!(msig.verify(tx, &addr), Err(MultisigError::InvalidAddress));
    }
}
