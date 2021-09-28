// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Implementation of a two-layer OTS scheme based on ECDSA-ED25519.
//!
//! A One Time Signature (OTS) is a cryptographic signature that is produced
//! a limited number of times and provides forward integrity.

use std::collections::VecDeque;
use std::convert::TryInto;
use std::sync::RwLock;

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::*;
use crate::protocol;

// TODO implement codecs
// TODO ensure codecs are compatible with go-algorand
//      (where necessary)

/// An OTS is generated from an ephemeral secret.
/// After some number of messages is signed under a given `OTSIdentifier` the corresponding secret is deleted.
/// This prevents the secret-holder from signing a contradictory message in the
/// future in the event of a secret-key compromise.
#[derive(Serialize, Deserialize)]
pub struct OTS {
    /// Signature of a message under the key pk.
    pub sig: Signature,
    pub pk: PublicKey,

    /// Old-style signature that does not use proper domain separation.
    /// It is unused; however, unfortunately go-algorand developers forgot to mark it
    /// `codec:omitempty` and so it appears (with zero value) in certs.
    /// This means we can't delete the field without breaking catchup.
    _pk_sig_old: Signature,

    /// Used to verify a new-style two-level ephemeral signature.
    pub pk2: PublicKey,

    /// Signature of `OTSSubkeyOffsetID(pk, batch, offset)` under the key `pk2`.
    pub pk1_sig: Signature,

    /// Signature of `OTSSubkeyBatchID(pk2, batch)` under the master key (`OTSVerifier`).
    pub pk2_sig: Signature,
}

/// An identifier under which OTSs are produced.
/// This identifier is represented using a two-level structure, which corresponds to our ephemeral key tree.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct OTSIdentifier {
    /// Most-significant part of the identifier.
    pub batch: u64,

    /// Least-significant part of the identifier.
    /// When moving to a new `batch`, the `offset` values restart from 0.
    pub offset: u64,
}

/// Identifies an `EphemeralSubkey` of a `batch` for the purposes of signing it with the top-level master key.
#[derive(Serialize, Deserialize)]
pub struct OTSSubkeyBatchID {
    pub sub_key_pk: PublicKey,
    pub batch: u64,
}

/// Identifies an EphemeralSubkey of a specific offset within a batch,
/// for the purposes of signing it with the batch subkey.
#[derive(Serialize, Deserialize)]
pub struct OTSSubkeyOffsetID {
    pub sub_key_pk: PublicKey,
    pub batch: u64,
    pub offset: u64,
}

pub type OTSVerifier = PublicKey;

/// Used for producing unforgeable signatures over a message.
///
/// When the method `OTSSecrets::delete_before(id)` is called,
/// ephemeral secrets corresponding to `OTSIdentifier`s preceding ID are deleted.
/// Thereafter, no different messages can be signed with old `OTSIdentifier`s,
/// permanently protecting the integrity of the messages signed under those identifiers.
#[derive(Serialize, Deserialize)]
pub struct OTSSecrets {
    pub verifier: OTSVerifier,

    /// First batch whose subkey appears in Batches.
    first_batch: u64,
    batches: VecDeque<EphemeralSubkey>,

    /// First offset whose subkey appears in offsets.
    /// These subkeys correspond to batch first_batch-1.
    first_offset: u64,
    offsets: VecDeque<EphemeralSubkey>,

    /// When offsets is non-empty, `offsets_pk2` is the intermediate-level public
    /// key that can be used to verify signatures on the subkeys in offsets.
    offsets_pk2: PublicKey,

    /// Signature from the master key (`OTSVerifier`) on `OTSSubkeyBatchID(offsets_pk2, first_batch-1)`.
    offsets_pk2_sig: Signature,

    /// Read-write lock to guard against concurrent invocations,
    /// such as sign() concurrently running with delete_before().
    lock: RwLock<()>,
}

impl OTSSecrets {
    /// Creates a limited number of secrets that sign messages under `OTSIdentifier`s in the range
    /// [start_batch, start_batch+num_batches), i.e. including start_batch and excludes start_batch+num_batches.
    pub fn generate(start_batch: u64, num_batches: u64) -> OTSSecrets {
        let kp = Keypair::generate(&mut OsRng {});
        let mut subkeys = VecDeque::with_capacity(num_batches.try_into().unwrap());

        for i in 0..num_batches {
            let kp_eph = Keypair::generate(&mut OsRng {});
            let batchnum = start_batch + i;

            let newid = OTSSubkeyBatchID {
                sub_key_pk: kp_eph.public,
                batch: batchnum,
            };
            let newsig = kp.sign(&newid.hash_rep());

            subkeys.push_back(EphemeralSubkey {
                kp: kp_eph,
                pk_sig_new: newsig,
            });
        }

        OTSSecrets {
            verifier: kp.public,
            first_batch: start_batch,
            batches: subkeys,

            lock: RwLock::new(()),
            offsets: VecDeque::new(),
            offsets_pk2: PublicKey::default(),
            offsets_pk2_sig: Signature::new([0; 64]),
            first_offset: 0,
        }
    }

    /// Produces a OTS of some Hashable message under some OTSIdentifier.
    pub fn sign(&self, id: &OTSIdentifier, message: &impl Hashable) -> OTS {
        let _guard = self.lock.read();

        // Check if we already have a partial batch of subkeys.
        if id.batch + 1 == self.first_batch
            && id.offset >= self.first_offset
            && id.offset - self.first_offset < self.offsets.len() as u64
        {
            let offidx = (id.offset - self.first_offset) as usize;
            let sig = self.offsets[offidx].kp.sign(&message.hash_rep());

            return OTS {
                sig,
                pk: self.offsets[offidx].kp.public,
                pk1_sig: self.offsets[offidx].pk_sig_new,
                pk2: self.offsets_pk2,
                pk2_sig: self.offsets_pk2_sig,
                _pk_sig_old: Signature::new([0; 64]),
            };
        }

        // Check if we are asking for an offset from an available batch.
        if id.batch >= self.first_batch && id.batch - self.first_batch < self.batches.len() as u64 {
            // Since we have not yet broken out this batch into per-offset keys,
            // generate a fresh subkey right away, sign it, and use it.
            let kp = Keypair::generate(&mut OsRng {});
            let sig = kp.sign(&message.hash_rep());

            let batchidx = (id.batch - self.first_batch) as usize;
            let pksig = self.batches[batchidx].pk_sig_new;

            let pk1id = OTSSubkeyOffsetID {
                sub_key_pk: kp.public,
                batch: id.batch,
                offset: id.offset,
            };

            return OTS {
                sig,
                pk: kp.public,
                pk1_sig: self.batches[batchidx].kp.sign(&pk1id.hash_rep()),
                pk2: self.batches[batchidx].kp.public,
                pk2_sig: pksig,
                _pk_sig_old: Signature::new([0; 64]),
            };
        }

        let msg = format!("tried to sign message with out-of-range one-time identifier {:?} (firstbatch={}, len(batches)={}, firstoffset={}, len(offsets)={})", id, self.first_batch, self.batches.len(), self.first_offset, self.offsets.len());

        // It's expected that we sometimes hit this error, when trying to sign
        // using an identifier of a block that we just reached agreement on and thus deleted.
        // Don't warn if we're out-of-range by just one.
        // This might still trigger a false warning if we're out-of-range by just one
        // and it happens to be a batch boundary, but we don't have the batch
        // size (key dilution) parameter accessible here easily.
        if self.first_batch == id.batch + 1 && self.first_offset == id.offset + 1 {
            info!("{}", msg);
        } else {
            warn!("{}", msg);
        }

        // TODO Default::default()?
        OTS {
            sig: Signature::new([0; 64]),
            pk: Default::default(),
            pk1_sig: Signature::new([0; 64]),
            pk2: Default::default(),
            pk2_sig: Signature::new([0; 64]),
            _pk_sig_old: Signature::new([0; 64]),
        }
    }

    /// Deletes ephemeral keys before (but not including) the given id.
    // TODO: Securely wipe the keys from memory. (is this done automatically in Drop?)
    pub fn delete_before(&mut self, current: OTSIdentifier, num_keys_per_batch: u64) {
        let _guard = self.lock.write().unwrap();

        // If we are just advancing in the same batch, simply delete some offset subkeys.
        if current.batch + 1 == self.first_batch {
            if current.offset > self.first_offset {
                let mut jump = current.offset - self.first_offset;
                if jump > self.offsets.len() as u64 {
                    jump = self.offsets.len() as u64;
                }

                self.first_offset += jump;
                self.offsets.drain(..jump as usize);
            }

            return;
        }

        // If we are trying to forget something earlier, there's nothing to do.
        if current.batch + 1 < self.first_batch {
            return;
        }

        // We are trying to move forward into a new batch. Four steps are necessary:
        // 1. Delete existing offsets.
        self.offsets.clear();

        // 2. Delete any whole batches that we are jumping over.
        let jump = current.batch - self.first_batch;
        if jump > self.batches.len() as u64 {
            // We ran out of whole batches.  Clear out everything.
            // If there weren't any batches to begin with, don't bother bumping `first_batch`,
            // so that we don't make irrelevant changes to expired keys.
            if !self.batches.is_empty() {
                self.first_batch = current.batch;
                self.batches.clear();
            }
            return;
        }
        self.first_batch += jump;
        self.batches.drain(..jump as usize);

        // 3. Expand the next batch into offset subkeys.
        if self.batches.is_empty() {
            // We ran out of whole batches.
            return;
        }

        self.offsets_pk2 = self.batches[0].kp.public;
        self.offsets_pk2_sig = self.batches[0].pk_sig_new;

        self.first_offset = current.offset;
        for off in current.offset..num_keys_per_batch {
            let kp = Keypair::generate(&mut OsRng {});
            let pksig = self.batches[0].kp.sign(
                &OTSSubkeyOffsetID {
                    sub_key_pk: kp.public,
                    batch: current.batch,
                    offset: off,
                }
                .hash_rep(),
            );
            self.offsets.push_back(EphemeralSubkey {
                kp,
                pk_sig_new: pksig,
            });
        }

        // 4. Delete the next batch subkey that we just expanded.
        self.first_batch += 1;
        self.batches.pop_front();
    }

    /// Returns a copy of OTSSecrets consistent with respect to concurrent mutating calls (specifically, delete_before).
    /// This snapshot can be used for serializing the OTSSecrets to persistent storage.
    pub fn snapshot(&self) -> Self {
        let _guard = self.lock.read();
        // TODO move into a Clone impl on OTSSecrets?
        // TODO do not clone at all? instead return reference and lock guard?
        OTSSecrets {
            verifier: self.verifier,
            first_batch: self.first_batch,
            batches: self.batches.clone(),
            first_offset: self.first_offset,
            offsets: self.offsets.clone(),
            offsets_pk2: self.offsets_pk2,
            offsets_pk2_sig: self.offsets_pk2_sig,
            lock: RwLock::new(()),
        }
    }
}

impl OTS {
    /// Verifies that some Hashable signature was signed under some
    /// OneTimeSignatureVerifier and some OneTimeSignatureIdentifier.
    ///
    /// It returns true if this is the case; otherwise, it returns false.
    pub fn verify(&self, id: &OTSIdentifier, msg: &impl Hashable, pk: &OTSVerifier) -> bool {
        let offset_id = OTSSubkeyOffsetID {
            sub_key_pk: self.pk,
            batch: id.batch,
            offset: id.offset,
        };
        let batch_id = OTSSubkeyBatchID {
            sub_key_pk: self.pk2,
            batch: id.batch,
        };

        // TODO verify_prehashed or verify_strict?
        pk.verify_strict(&batch_id.hash_rep(), &self.pk2_sig)
            .is_ok()
            && batch_id
                .sub_key_pk
                .verify_strict(&offset_id.hash_rep(), &self.pk1_sig)
                .is_ok()
            && offset_id
                .sub_key_pk
                .verify_strict(&msg.hash_rep(), &self.sig)
                .is_ok()
    }
}

impl Hashable for OTSSubkeyBatchID {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::ONE_TIME_SIG_KEY1, protocol::encode(&self))
    }
}

impl Hashable for OTSSubkeyOffsetID {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::ONE_TIME_SIG_KEY2, protocol::encode(&self))
    }
}

/// Produces OTSs for messages and is deleted after use.
#[derive(Serialize, Deserialize)]
struct EphemeralSubkey {
    pub kp: Keypair,

    /// The signature that authenticates PK, signed using the
    /// Hashable interface for domain separation (the Hashable object is either
    /// OTSSubkeyBatchID or OTSSubkeyOffsetID).
    pub pk_sig_new: Signature,
}

impl Clone for EphemeralSubkey {
    fn clone(&self) -> Self {
        EphemeralSubkey {
            kp: Keypair::from_bytes(&self.kp.to_bytes()).unwrap(),
            pk_sig_new: self.pk_sig_new,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{distributions::Alphanumeric, thread_rng, Rng, RngCore};

    #[test]
    fn verify() {
        let mut c = OTSSecrets::generate(0, 1000);
        let c2 = OTSSecrets::generate(0, 1000);

        let id = rand_id();
        let s = rand_string();
        let s2 = rand_string();

        let sig = c.sign(&id, &s);
        assert!(
            sig.verify(&id, &s, &c.verifier),
            "correct signature failed to verify"
        );
        assert!(
            !sig.verify(&id, &s2, &c.verifier),
            "signature verifies on wrong message"
        );

        let sig2 = c2.sign(&id, &s);
        assert!(
            !sig2.verify(&id, &s, &c.verifier),
            "wrong master key incorrectly verified"
        );

        let other_id = rand_id();
        assert!(
            !sig.verify(&other_id, &s, &c.verifier),
            "signature verifies for wrong ID"
        );

        let mut next_offset_id = id;
        next_offset_id.offset += 1;
        assert!(
            !sig.verify(&next_offset_id, &s, &c.verifier),
            "signature verifies after changing offset"
        );

        c.delete_before(next_offset_id, 256);
        let sig_after_delete = c.sign(&id, &s);
        assert!(
            !sig_after_delete.verify(&id, &s, &c.verifier),
            "signature verifies after delete offset"
        );

        let sig_next_after_delete = c.sign(&next_offset_id, &s);
        assert!(
            sig_next_after_delete.verify(&next_offset_id, &s, &c.verifier),
            "signature fails to verify after deleting up to this offset"
        );

        next_offset_id.offset += 1;
        let sig_next_2_after_delete = c.sign(&next_offset_id, &s);
        assert!(
            sig_next_2_after_delete.verify(&next_offset_id, &s, &c.verifier),
            "signature fails to verify after deleting up to previous offset"
        );

        let mut next_batch_id = id;
        next_batch_id.batch += 1;

        let mut next_batch_offset_id = next_batch_id;
        next_batch_offset_id.offset += 1;
        c.delete_before(next_batch_offset_id, 256);
        let sig_after_delete = c.sign(&next_batch_id, &s);
        assert!(
            !sig_after_delete.verify(&next_batch_id, &s, &c.verifier),
            "signature verifies after delete"
        );

        let sig_next_after_delete = c.sign(&next_batch_offset_id, &s);
        assert!(
            sig_next_after_delete.verify(&next_batch_offset_id, &s, &c.verifier),
            "signature fails to verify after delete up to this offset"
        );

        next_batch_offset_id.offset += 1;
        let sig_next_2_after_delete = c.sign(&next_batch_offset_id, &s);
        assert!(
            sig_next_2_after_delete.verify(&next_batch_offset_id, &s, &c.verifier),
            "signature fails to verify after delete up to previous offset"
        );

        let mut big_jump_id = next_batch_offset_id;
        big_jump_id.batch += 10;
        c.delete_before(big_jump_id, 256);

        let mut pre_big_jump_id = big_jump_id;
        pre_big_jump_id.batch -= 1;
        let sig = c.sign(&pre_big_jump_id, &s);
        assert!(!sig.verify(&pre_big_jump_id, &s, &c.verifier));

        pre_big_jump_id.batch += 1;
        pre_big_jump_id.offset -= 1;
        let sig = c.sign(&pre_big_jump_id, &s);
        assert!(!sig.verify(&pre_big_jump_id, &s, &c.verifier));
        let sig = c.sign(&big_jump_id, &s);
        assert!(sig.verify(&big_jump_id, &s, &c.verifier));

        big_jump_id.offset += 1;
        let sig = c.sign(&big_jump_id, &s);
        assert!(sig.verify(&big_jump_id, &s, &c.verifier));

        big_jump_id.batch += 1;
        let sig = c.sign(&big_jump_id, &s);
        assert!(sig.verify(&big_jump_id, &s, &c.verifier));
    }

    fn rand_id() -> OTSIdentifier {
        let mut rng = thread_rng();
        OTSIdentifier {
            batch: rng.next_u64() % 256,

            // Avoid generating the last few offsets (in a batch size of 256), so we can increment correctly.
            offset: rng.next_u64() % 250,
        }
    }

    fn rand_string() -> String {
        let s: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .collect();
        return s;
    }
}
