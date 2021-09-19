// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryInto;

use ed25519::Signature;
use ed25519_dalek::{Keypair, PublicKey, Signer};
use sha2::{Digest, Sha512Trunc256};

use crate::crypto::batch_verifier::BatchVerifier;

const MAX_MULTISIG: u8 = 255;

// TODO implement and use Hashable trait
// TODO make this more struct/impl oriented than just using functions passing sig/verifier

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultisigError {
    UnknownVersion(u8),
    InvalidThreshold,
    InvalidSignature,
    InvalidAddress,
    InvalidNumberOfSignatures,
    KeyNotExists,
    ThresholdsDontMatch(u8, u8),
    VersionsDontMatch(u8, u8),
    KeysDontMatch,
    InvalidDuplicates,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct MultisigSubsig {
    pub key: PublicKey,
    pub sig: Option<Signature>,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct MultisigSignature {
    pub version: u8,
    pub threshold: u8,
    pub subsigs: Vec<MultisigSubsig>,
}

fn gen_multisig_addr(
    version: u8,
    threshold: u8,
    pks: &Vec<PublicKey>,
) -> Result<[u8; 32], MultisigError> {
    if version != 1 {
        return Err(MultisigError::UnknownVersion(version));
    }

    if threshold == 0 || pks.len() == 0 || threshold as usize > pks.len() {
        return Err(MultisigError::InvalidThreshold);
    }

    let mut buf = b"MultisigAddr".to_vec();
    buf.push(version);
    buf.push(threshold);

    for pk in pks {
        buf.extend(pk.as_bytes());
    }

    return Ok(Sha512Trunc256::digest(&buf).try_into().unwrap());
}

// MultisigAddrGenWithSubsigs is similar to MultisigAddrGen
// except the input is []Subsig rather than []PublicKey
fn gen_multisig_addr_with_subsigs(
    version: u8,
    threshold: u8,
    subsigs: &Vec<MultisigSubsig>,
) -> Result<[u8; 32], MultisigError> {
    let pks = subsigs.iter().map(|s| s.key).collect();
    return gen_multisig_addr(version, threshold, &pks);
}

/// Has to be called for each signing party individually.
fn sign(
    msg: &[u8],
    addr: [u8; 32],
    version: u8,
    threshold: u8,
    pks: &Vec<PublicKey>,
    kp: &Keypair,
) -> Result<MultisigSignature, MultisigError> {
    if version != 1 {
        return Err(MultisigError::UnknownVersion(version));
    }

    // check the address matches the keys
    let addr_new = gen_multisig_addr(version, threshold, &pks)?;

    if addr != addr_new {
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
    for i in 0..pks.len() {
        sig.subsigs.push(MultisigSubsig {
            key: pks[i],
            sig: None,
        });
        if kp.public == pks[i] {
            sig.subsigs[i].sig = Some(kp.sign(&msg));
        }
    }

    return Ok(sig);
}

/// Combines multiple `MultisigSignature` into one
fn assemble(unisig: &Vec<MultisigSignature>) -> Result<MultisigSignature, MultisigError> {
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

    return Ok(msig);
}

fn verify(msg: &[u8], addr: [u8; 32], sig: &MultisigSignature) -> Result<bool, MultisigError> {
    let mut batch_verifier = BatchVerifier::new();

    if !batch_verify(msg, addr, sig, &mut batch_verifier)? {
        return Ok(false);
    }

    if batch_verifier.num_sigs_enqued() == 0 {
        return Ok(true);
    }

    return Ok(batch_verifier.verify().is_ok());
}

// MultisigBatchVerify verifies an assembled MultisigSig.
// it is the caller responsibility to call batchVerifier.verify()
fn batch_verify(
    msg: &[u8],
    addr: [u8; 32],
    sig: &MultisigSignature,
    batch_verifier: &mut BatchVerifier,
) -> Result<bool, MultisigError> {
    // short circuit: if msig doesn't have subsigs or if Subsigs are empty
    // then terminate (the upper layer should now verify the unisig)
    if sig.subsigs.len() == 0 || sig.subsigs[0] == MultisigSubsig::default() {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    // check the address is correct
    let addrnew = gen_multisig_addr_with_subsigs(sig.version, sig.threshold, &sig.subsigs)?;
    if addr != addrnew {
        return Err(MultisigError::InvalidAddress);
    }

    // check that we don't have too many multisig subsigs
    if sig.subsigs.len() > MAX_MULTISIG as usize {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    // check that we don't have too few multisig subsigs
    if sig.subsigs.len() < sig.threshold as usize {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    // checks the number of non-blank signatures is no less than threshold
    let non_empty = sig.subsigs.iter().filter(|s| s.sig.is_some()).count();
    if non_empty < sig.threshold as usize {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    // checks individual signature verifies
    let mut verified = 0;
    for sub_sig in &sig.subsigs {
        if let Some(s) = sub_sig.sig {
            batch_verifier.enque_sig(sub_sig.key, msg, s);
            verified += 1;
        }
    }

    // sanity check. if we get here then every non-blank subsig should have
    // been verified successfully, and we should have had enough of them
    if verified < sig.threshold {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    return Ok(true);
}

/// Adds unisigs to an existing msig.
fn add_sigs(
    unisigs: Vec<MultisigSignature>,
    msig: &mut MultisigSignature,
) -> Result<(), MultisigError> {
    if unisigs.is_empty() {
        return Err(MultisigError::InvalidNumberOfSignatures);
    }

    // check if all unisig match
    // TODO write function for this match check!
    for unisig in &unisigs {
        if msig.threshold != unisig.threshold {
            return Err(MultisigError::ThresholdsDontMatch(
                msig.threshold,
                unisig.threshold,
            ));
        } else if msig.version != unisig.version {
            return Err(MultisigError::VersionsDontMatch(
                msig.version,
                unisig.version,
            ));
        } else if msig.subsigs.len() != unisig.subsigs.len() {
            return Err(MultisigError::KeysDontMatch);
        }

        for i in 0..unisigs[0].subsigs.len() {
            if msig.subsigs[i].key != unisig.subsigs[i].key {
                return Err(MultisigError::KeysDontMatch);
            }
        }
    }

    // update the msig
    for i in 0..unisigs.len() {
        for j in 0..msig.subsigs.len() {
            if unisigs[i].subsigs[j].sig.is_some() {
                if msig.subsigs[j].sig.is_none() {
                    // add the signature
                    msig.subsigs[j].sig = unisigs[i].subsigs[j].sig;
                } else if msig.subsigs[j].sig != unisigs[i].subsigs[j].sig {
                    // invalid duplicates
                    return Err(MultisigError::InvalidDuplicates);
                } else {
                    // valid duplicates
                }
            }
        }
    }

    return Ok(());
}

// MultisigMerge merges two Multisigs msig1 and msig2 into msigt
fn merge(
    msig1: &MultisigSignature,
    msig2: &MultisigSignature,
) -> Result<MultisigSignature, MultisigError> {
    // TODO write function for this match check!
    // check if all parameters match
    if msig1.threshold != msig2.threshold
        || msig1.version != msig2.version
        || msig1.subsigs.len() != msig2.subsigs.len()
    {
        return Err(MultisigError::InvalidThreshold);
    }

    for i in 0..msig1.subsigs.len() {
        if msig1.subsigs[i].key != msig2.subsigs[i].key {
            return Err(MultisigError::KeysDontMatch);
        }
    }
    // update msigt
    let mut msig = MultisigSignature {
        version: msig1.version,
        threshold: msig1.threshold,
        subsigs: Vec::with_capacity(msig1.subsigs.len()),
    };

    for i in 0..msig1.subsigs.len() {
        msig.subsigs.push(MultisigSubsig {
            key: msig1.subsigs[i].key,
            sig: None,
        });

        if msig1.subsigs[i].sig.is_none() {
            if msig2.subsigs[i].sig.is_some() {
                // update signature with msig2's signature
                msig.subsigs[i].sig = msig2.subsigs[i].sig;
            }
        } else if msig2.subsigs[i].sig.is_none() || // msig2's sig is empty
			msig2.subsigs[i].sig == msig1.subsigs[i].sig
        {
            // valid duplicates
            // update signature with msig1's signature
            msig.subsigs[i].sig = msig1.subsigs[i].sig;
        } else {
            // invalid duplicates
            return Err(MultisigError::InvalidDuplicates);
        }
    }

    return Ok(msig);
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
        let result = gen_multisig_addr(version, threshold, &pks);
        assert_eq!(result, Err(MultisigError::InvalidThreshold));

        // keys == threshold
        pks.push(kps[2].public);
        let result = gen_multisig_addr(version, threshold, &pks);
        assert_eq!(result.is_ok(), true);

        // keys > threshold
        pks.push(kps[3].public);
        let result = gen_multisig_addr(version, threshold, &pks);
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

        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        assert_eq!(
            addr,
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
        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();

        // invalid version
        let result = sign(tx, addr, version + 1, threshold, &pks, &kps[0]);
        assert_eq!(result.is_err(), true);

        // invalid secret key
        let result = sign(tx, addr, version, threshold, &pks, &kps[4]);
        assert_eq!(result, Err(MultisigError::KeyNotExists));

        // single signature (3 required)
        let sigs = vec![sign(tx, addr, version, threshold, &pks, &kps[3]).unwrap()];
        let result = assemble(&sigs);
        assert_eq!(result, Err(MultisigError::InvalidNumberOfSignatures));

        // assemble 3 signatures
        let mut sigs = Vec::new();
        for i in 0..3 {
            sigs.push(sign(tx, addr, version, threshold, &pks, &kps[i]).unwrap());
        }
        let msig = assemble(&sigs).unwrap();
        assert_eq!(verify(tx, addr, &msig).unwrap(), true);

        // batch verification
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(batch_verify(tx, addr, &msig, &mut bv), Ok(true));
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

        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let empty_sig = MultisigSignature {
            version: version,
            threshold: threshold,
            subsigs: Vec::new(),
        };
        assert_eq!(
            verify(tx, addr, &empty_sig),
            Err(MultisigError::InvalidNumberOfSignatures)
        );

        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            batch_verify(tx, addr, &empty_sig, &mut bv),
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

        for i in 0..5 {
            rng.fill_bytes(&mut seed);
            let secret = SecretKey::from_bytes(&seed).unwrap();
            let public = (&secret).into();
            kps.push(Keypair { secret, public });
            pks.push(public);
        }

        // addr = hash (... |pk0|pk1|pk2|pk3|pk4)
        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();

        // msig1 = {sig0,sig1}
        let mut sigs = Vec::new();
        sigs.push(sign(tx, addr, version, threshold, &pks, &kps[0]).unwrap());
        sigs.push(sign(tx, addr, version, threshold, &pks, &kps[1]).unwrap());
        let mut msig1 = assemble(&sigs).unwrap();
        // add sig3 to msig and then verify
        let sigs = vec![sign(tx, addr, version, threshold, &pks, &kps[2]).unwrap()];
        add_sigs(sigs, &mut msig1).unwrap();
        assert_eq!(verify(tx, addr, &msig1), Ok(true));

        // msig2 = {sig3, sig4}
        let mut sigs = Vec::new();
        sigs.push(sign(tx, addr, version, threshold, &pks, &kps[3]).unwrap());
        sigs.push(sign(tx, addr, version, threshold, &pks, &kps[4]).unwrap());
        let mut msig2 = assemble(&sigs).unwrap();
        // merge two msigs and then verify
        let msig = merge(&msig1, &msig2).unwrap();
        assert_eq!(verify(tx, addr, &msig), Ok(true));

        // create a valid duplicate on purpose
        // msig1 = {sig0, sig1, sig2}
        // msig2 = {sig2, sig3, sig4}
        // then verify the merged signature
        let sigs = vec![sign(tx, addr, version, threshold, &pks, &kps[2]).unwrap()];
        add_sigs(sigs, &mut msig2).unwrap();
        let msig = merge(&msig1, &msig2).unwrap();
        assert_eq!(verify(tx, addr, &msig), Ok(true));
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

        let mut addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let msig = sign(tx, addr, version, threshold, &pks, &kp).unwrap();
        addr[0] = addr[0] + 1;
        assert_eq!(verify(tx, addr, &msig), Err(MultisigError::InvalidAddress));
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            batch_verify(tx, addr, &msig, &mut bv),
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

        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..MAX_MULTISIG as usize + 1 {
            sigs.push(sign(tx, addr, version, threshold, &pks, &kps[i]).unwrap());
        }

        let msig = assemble(&sigs).unwrap();
        assert_eq!(
            verify(tx, addr, &msig),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            batch_verify(tx, addr, &msig, &mut bv),
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

        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..multisig_len {
            sigs.push(sign(tx, addr, version, threshold, &pks, &kps[i]).unwrap());
        }

        let mut msig = assemble(&sigs).unwrap();
        msig.subsigs[0].sig = None;
        assert_eq!(
            verify(tx, addr, &msig),
            Err(MultisigError::InvalidNumberOfSignatures)
        );
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(
            batch_verify(tx, addr, &msig, &mut bv),
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

        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();

        for i in 0..multisig_len {
            sigs.push(sign(tx, addr, version, threshold, &pks, &kps[i]).unwrap());
        }

        // break one signature
        let mut sig_bytes = sigs[1].subsigs[1].sig.unwrap().to_bytes();
        sig_bytes[5] += 1;
        sigs[1].subsigs[1].sig = Some(Signature::new(sig_bytes));

        let msig = assemble(&sigs).unwrap();
        assert_eq!(verify(tx, addr, &msig), Ok(false));
        let mut bv = BatchVerifier::with_capacity(1);
        assert_eq!(batch_verify(tx, addr, &msig, &mut bv), Ok(true));
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
        let addr = gen_multisig_addr(version, threshold, &pks).unwrap();
        let mut sigs = Vec::new();
        for i in 0..3 {
            sigs.push(sign(tx, addr, version, threshold, &pks, &kps[i]).unwrap());
        }

        let mut msig = assemble(&sigs).unwrap();
        msig.subsigs[1].sig = None;
        assert_eq!(
            verify(tx, addr, &msig),
            Err(MultisigError::InvalidNumberOfSignatures)
        );

        let mut msig = assemble(&sigs).unwrap();
        msig.subsigs.pop();
        assert_eq!(verify(tx, addr, &msig), Err(MultisigError::InvalidAddress));
    }
}
