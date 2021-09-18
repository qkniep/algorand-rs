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

fn verify(msg: &[u8], addr: [u8; 32], sig: MultisigSignature) -> Result<bool, MultisigError> {
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
    sig: MultisigSignature,
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
    for sub_sig in sig.subsigs {
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

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{SecretKey, SECRET_KEY_LENGTH};
    use rand::{thread_rng, RngCore};

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

    // this test generates a set of 4 public keys for a threshold of 3
    // signs with 3 keys to get 3 signatures
    // assembles 3 signatures, verify the msig
    #[test]
    fn multisig() {
        let version = 1;
        let threshold = 3;

        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        let mut kps = Vec::with_capacity(5);
        let mut pks = Vec::with_capacity(4);

        let tx = b"test: txid 1000";

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
        assert_eq!(verify(tx, addr, msig).unwrap(), true);

        /*
        // batch verification
        bv = MakeBatchVerifier(1);
        let verify, err = multisig_(txid, addr, msig, br)
        require.NoError(t, err, "Multisig: unexpected verification failure with err")
        require.True(t, verify, "Multisig: verification failed, verify flag was false")
        res := br.Verify()
        require.NoError(t, res, "Multisig: batch verification failed")
        */
    }
}
