// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::cmp::max;

use ed25519_dalek::{PublicKey, Signature, Verifier};

// TODO add benchmark

const MIN_CAPACITY: usize = 16;

pub struct BatchVerifier {
    //messages   Vec<Hashable>          // contains a slice of messages to be hashed. Each message is varible length
    messages: Vec<Vec<u8>>, // contains a slice of messages to be hashed. Each message is varible length
    public_keys: Vec<PublicKey>, // contains a slice of public keys. Each individual public key is 32 bytes.
    signatures: Vec<Signature>, // contains a slice of signatures keys. Each individual signature is 64 bytes.
}

#[derive(Debug, PartialEq, Eq)]
pub enum BatchVerError {
    VerificationFailed,
    ZeroTranscationsInBatch,
}

impl BatchVerifier {
    // MakeBatchVerifierDefaultSize create a BatchVerifier instance. This function pre-allocates
    // amount of free space to enqueue signatures without exapneding
    pub fn new() -> Self {
        return Self::with_capacity(MIN_CAPACITY);
    }

    // MakeBatchVerifier create a BatchVerifier instance. This function pre-allocates
    // a given space so it will not expaned the storage
    pub fn with_capacity(capacity: usize) -> Self {
        // preallocate enough storage for the expected usage. We will reallocate as needed.
        let capacity = max(capacity, MIN_CAPACITY);
        return BatchVerifier {
            messages: Vec::with_capacity(capacity),
            public_keys: Vec::with_capacity(capacity),
            signatures: Vec::with_capacity(capacity),
        };
    }

    pub fn enque_sig(&mut self, pk: PublicKey, msg: &[u8], sig: Signature) {
        self.messages.push(msg.to_vec());
        self.public_keys.push(pk);
        self.signatures.push(sig);
    }

    // GetNumberOfEnqueuedSignatures returns the number of signatures current enqueue onto the bacth verifier object
    pub fn num_sigs_enqued(&self) -> usize {
        return self.messages.len();
    }

    // Verify verifies that all the signatures are valid. in that case nil is returned
    // if the batch is zero an appropriate error is return.
    pub fn verify(&self) -> Result<(), BatchVerError> {
        if self.num_sigs_enqued() == 0 {
            return Err(BatchVerError::ZeroTranscationsInBatch);
        }

        for i in 0..self.messages.len() {
            if self.public_keys[i]
                .verify(&self.messages[i], &self.signatures[i])
                .is_err()
            {
                return Err(BatchVerError::VerificationFailed);
            }
        }

        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::{Keypair, SecretKey, Signer, SECRET_KEY_LENGTH};
    use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

    #[test]
    fn signle() {
        let mut bv = BatchVerifier::with_capacity(1);
        let msg = random_string();
        let kp = new_kp();
        let sig = kp.sign(&msg);
        bv.enque_sig(kp.public, &msg, sig);
        assert_eq!(bv.verify(), Ok(()));
    }

    #[test]
    fn bulk() {
        for i in 1..64 * 2 + 3 {
            let n = i;
            let mut bv = BatchVerifier::with_capacity(1);

            for _ in 0..n {
                let msg = random_string();
                let kp = new_kp();
                let sig = kp.sign(&msg);
                bv.enque_sig(kp.public, &msg, sig)
            }

            assert_eq!(bv.num_sigs_enqued(), n);
            assert_eq!(bv.verify(), Ok(()));
        }
    }

    #[test]
    fn invalid_sig() {
        // TODO flaky test?
        let n = 64;
        let mut bv = BatchVerifier::with_capacity(1);

        for _ in 0..n - 1 {
            let msg = random_string();
            let kp = new_kp();
            let sig = kp.sign(&msg);
            bv.enque_sig(kp.public, &msg, sig);
        }

        let msg = random_string();
        let kp = new_kp();
        let mut sig = kp.sign(&msg);

        // break signature by modifying one byte
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] = sig_bytes[0] + 1;
        sig = Signature::new(sig_bytes);

        bv.enque_sig(kp.public, &msg, sig);

        assert_eq!(bv.verify(), Err(BatchVerError::VerificationFailed));
    }

    #[test]
    fn empty_batch() {
        let bv = BatchVerifier::new();
        assert_eq!(bv.verify(), Err(BatchVerError::ZeroTranscationsInBatch));
    }

    fn new_kp() -> Keypair {
        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut seed);
        let secret = SecretKey::from_bytes(&seed).unwrap();
        let public = (&secret).into();
        return Keypair { secret, public };
    }

    fn random_string() -> Vec<u8> {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(|c| c as u8)
            .collect()
    }
}
