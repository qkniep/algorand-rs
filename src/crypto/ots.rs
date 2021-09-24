// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! Implementation of a two-layer OTS scheme based on ECDSA-ED25519.

use std::convert::TryInto;
use std::sync::RwLock;

use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use super::*;
use crate::protocol;

// TODO implement codecs
// TODO ensure codecs are compatible with go-algorand
//      (where necessary)

/// A One Time Signature (OTS) is a cryptographic signature that is produced
/// a limited number of times and provides forward integrity.
///
/// Specifically, an OTS is generated from an ephemeral secret.
/// After some number of messages is signed under a given OTSIdentifier
/// the corresponding secret is deleted.
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

    // Used to verify a new-style two-level ephemeral signature.
    // PK1Sig is a signature of OneTimeSignatureSubkeyOffsetID(PK, Batch, Offset) under the key PK2.
    // PK2Sig is a signature of OneTimeSignatureSubkeyBatchID(PK2, Batch) under the master key (OneTimeSignatureVerifier).
    pub pk2: PublicKey,
    pub pk1_sig: Signature,
    pub pk2_sig: Signature,
}

/// An identifier under which an OTS is produced on a given message.
/// This identifier is represented using a two-level structure,
/// which corresponds to two levels of our ephemeral key tree.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct OTSIdentifier {
    /// Most-significant part of the identifier.
    pub batch: u64,

    /// Least-significant part of the identifier.
    /// When moving to a new Batch, the Offset values restart from 0.
    pub offset: u64,
}

/// Identifies an EphemeralSubkey of a batch for the purposes of signing it with the top-level master key.
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
/// Thereafter, an entity can no longer sign different messages with old `OTSIdentifier`s,
/// protecting the integrity of the messages signed under those identifiers.
#[derive(Serialize, Deserialize)]
// TODO use VecDeque instead of Vec for batches and offsets to facilitate deletions
pub struct OTSSecrets {
    verifier: OTSVerifier,

    /// First batch whose subkey appears in Batches.
    first_batch: u64,
    batches: Vec<EphemeralSubkey>,

    /// First offset whose subkey appears in offsets.
    /// These subkeys correspond to batch first_batch-1.
    first_offset: u64,
    offsets: Vec<EphemeralSubkey>,

    // When offsets is non-empty, `offsets_pk2` is the intermediate-level public
    // key that can be used to verify signatures on the subkeys in offsets, and
    // `offsets_pk2_sig` is the signature from the master key (OTSVerifier)
    // on `OTSSubkeyBatchID(offsets_pk2, first_batch-1)`.
    offsets_pk2: PublicKey,
    offsets_pk2_sig: Signature,

    /// Read-write lock to guard against concurrent invocations,
    /// such as sign() concurrently running with delete_before*().
    lock: RwLock<()>,
}

impl OTSSecrets {
    /// Creates a limited number of secrets that sign messages under `OTSIdentifier`s in the range
    /// [start_batch, start_batch+num_batches), i.e. including start_batch and excludes start_batch+num_batches.
    fn generate(start_batch: u64, num_batches: u64) -> OTSSecrets {
        let kp = Keypair::generate(&mut OsRng {});
        let mut subkeys = Vec::with_capacity(num_batches.try_into().unwrap());

        for i in 0..num_batches {
            let kp_eph = Keypair::generate(&mut OsRng {});
            let batchnum = start_batch + i;

            let newid = OTSSubkeyBatchID {
                sub_key_pk: kp_eph.public,
                batch: batchnum,
            };
            let newsig = kp.sign(&newid.hash_rep());

            subkeys.push(EphemeralSubkey {
                kp: kp_eph,
                pk_sig_new: newsig,
            });
        }

        return OTSSecrets {
            verifier: kp.public,
            first_batch: start_batch,
            batches: subkeys,

            lock: RwLock::new(()),
            offsets: Vec::new(),
            offsets_pk2: PublicKey::default(),
            offsets_pk2_sig: Signature::new([0; 64]),
            first_offset: 0,
        };
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

        /*errmsg := fmt.Sprintf("tried to sign %v with out-of-range one-time identifier %v (firstbatch %d, len(batches) %d, firstoffset %d, len(offsets) %d)",
        message, id, s.FirstBatch, len(s.Batches), s.FirstOffset, len(s.Offsets))*/

        // It's expected that we sometimes hit this error, when trying to sign
        // using an identifier of a block that we just reached agreement on and thus deleted.
        // Don't warn if we're out-of-range by just one.
        // This might still trigger a false warning if we're out-of-range by just one
        // and it happens to be a batch boundary, but we don't have the batch
        // size (key dilution) parameter accessible here easily.
        if self.first_batch == id.batch + 1 && self.first_offset == id.offset + 1 {
            //logging.Base().Info(errmsg)
        } else {
            //logging.Base().Warn(errmsg)
        }

        // TODO Default::default()?
        return OTS {
            sig: Signature::new([0; 64]),
            pk: Default::default(),
            pk1_sig: Signature::new([0; 64]),
            pk2: Default::default(),
            pk2_sig: Signature::new([0; 64]),
            _pk_sig_old: Signature::new([0; 64]),
        };
    }

    /// Deletes ephemeral keys before (but not including) the given id.
    // TODO: Securely wipe the keys from memory.
    fn delete_before_fine_grained(&mut self, current: OTSIdentifier, num_keys_per_batch: u64) {
        self.lock.write();

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
            self.offsets.push(EphemeralSubkey {
                kp,
                pk_sig_new: pksig,
            });
        }

        // 4. Delete the next batch subkey that we just expanded.
        self.first_batch += 1;
        self.batches.drain(..1);
    }

    /*
    /// Returns a copy of OTSSecrets consistent with respect to concurrent mutating calls
    /// (specifically, delete_before*).
    /// This snapshot can be used for serializing the OTSSecrets to persistent storage.
    fn snapshot(&self) -> Self {
        let _guard = self.lock.read();
        let mut ots_sec = (*self).clone();
        ots_sec.lock = RwLock::new(());
        return ots_sec;
    }
    */
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
        if pk
            .verify_strict(&batch_id.hash_rep(), &self.pk2_sig)
            .is_err()
        {
            return false;
        } else if batch_id
            .sub_key_pk
            .verify_strict(&offset_id.hash_rep(), &self.pk1_sig)
            .is_err()
        {
            return false;
        } else if offset_id
            .sub_key_pk
            .verify_strict(&msg.hash_rep(), &self.sig)
            .is_err()
        {
            return false;
        }
        return true;
    }
}

impl Hashable for OTSSubkeyBatchID {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        // TODO change when protocol::encode is implemented
        (protocol::ONE_TIME_SIG_KEY1, Vec::new())
        //return (protocol::ONE_TIME_SIG_KEY1, protocol::encode(&self));
    }
}

impl Hashable for OTSSubkeyOffsetID {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        // TODO change when protocol::encode is implemented
        (protocol::ONE_TIME_SIG_KEY2, Vec::new())
        //return (protocol::ONE_TIME_SIG_KEY2, protocol::encode(&self));
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

        c.delete_before_fine_grained(next_offset_id, 256);
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
        c.delete_before_fine_grained(next_batch_offset_id, 256);
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
        c.delete_before_fine_grained(big_jump_id, 256);

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
