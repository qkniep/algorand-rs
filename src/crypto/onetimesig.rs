// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::sync::RwLock;

use ed25519_dalek::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

// TODO implement codecs
// TODO ensure codecs are compatible with go-algorand

/// A One Time Signature (OTS) is a cryptographic signature that is produced
/// a limited number of times and provides forward integrity.
///
/// Specifically, an OTS is generated from an ephemeral secret.
/// After some number of messages is signed under a given OTSIdentifier
/// the corresponding secret is deleted.
/// This prevents the secret-holder from signing a contradictory message in the
/// future in the event of a secret-key compromise.
///
//#[derive(Serialize, Deserialize)]
pub struct OTS {
    /// Signature of msg under the key pk.
    pub sig: Signature,
    pub pk: PublicKey,

    // Old-style signature that does not use proper domain separation.
    // PKSigOld is unused; however, unfortunately we forgot to mark it
    // `codec:omitempty` and so it appears (with zero value) in certs.
    // This means we can't delete the field without breaking catchup.
    _pk_sig_old: Signature,

    // Used to verify a new-style two-level ephemeral signature.
    // PK1Sig is a signature of OneTimeSignatureSubkeyOffsetID(PK, Batch, Offset) under the key PK2.
    // PK2Sig is a signature of OneTimeSignatureSubkeyBatchID(PK2, Batch) under the master key (OneTimeSignatureVerifier).
    pub pk2: PublicKey,
    pub pk1_sig: Signature,
    pub pk2_sig: Signature,
}

/// A OneTimeSignatureIdentifier is an identifier under which a OneTimeSignature is
/// produced on a given message.  This identifier is represented using a two-level
/// structure, which corresponds to two levels of our ephemeral key tree.
#[derive(Serialize, Deserialize)]
pub struct OTSIdentifier {
    /// Most-significant part of the identifier.
    pub batch: u64,

    /// Least-significant part of the identifier.
    /// When moving to a new Batch, the Offset values restart from 0.
    pub offset: u64,
}

/// A OneTimeSignatureSubkeyBatchID identifies an ephemeralSubkey of a batch
/// for the purposes of signing it with the top-level master key.
//#[derive(Serialize, Deserialize)]
pub struct OTSSubkeyBatchID {
    pub sub_key_pk: PublicKey,
    pub batch: u64,
}

/// A OneTimeSignatureSubkeyOffsetID identifies an ephemeralSubkey of a specific
/// offset within a batch, for the purposes of signing it with the batch subkey.
//#[derive(Serialize, Deserialize)]
pub struct OTSSubkeyOffsetID {
    pub sub_key_pk: PublicKey,
    pub batch: u64,
    pub offset: u64,
}

pub type OTSVerifier = PublicKey;

/// OneTimeSignatureSecrets are used to produced unforgeable signatures over a
/// message.
///
/// When the method OneTimeSignatureSecrets.DeleteBefore(ID) is called, ephemeral
/// secrets corresponding to OneTimeSignatureIdentifiers preceding ID are
/// deleted. Thereafter, an entity can no longer sign different messages with old
/// OneTimeSignatureIdentifiers, protecting the integrity of the messages signed
/// under those identifiers.
//#[derive(Serialize, Deserialize)]
pub struct OTSSecrets {
    persist: OTSSecretsPersistent,

    // We keep track of an RNG, used to generate additional randomness.
    // This is used purely for testing (fuzzing, specifically). Except
    // for testing, the RNG is SystemRNG.
    //rng: Rng,

    // We use a read-write lock to guard against concurrent invocations,
    // such as Sign() concurrently running with DeleteBefore*().
    lock: RwLock<()>,
}

/// OTSSecretsPersistent denotes the fields of a OTSSecrets that get stored
/// to persistent storage (through reflection on exported fields).
//#[derive(Serialize, Deserialize)]
pub struct OTSSecretsPersistent {
    verifier: OTSVerifier,

    /// First batch whose subkey appears in Batches.
    // The odd `codec:` name is for backwards compatibility with previous
    // stored keys where we failed to give any explicit `codec:` name.
    first_batch: u64,
    batches: Vec<EphemeralSubkey>,

    /// First offset whose subkey appears in offsets.
    /// These subkeys correspond to batch first_batch-1.
    first_offset: u64,
    offsets: Vec<EphemeralSubkey>,

    // When Offsets is non-empty, OffsetsPK2 is the intermediate-level public
    // key that can be used to verify signatures on the subkeys in Offsets, and
    // OffsetsPK2Sig is the signature from the master key (OneTimeSignatureVerifier)
    // on OneTimeSignatureSubkeyBatchID(OffsetsPK2, FirstBatch-1).
    offsets_pk2: PublicKey,
    offsets_pk2_sig: Signature,
}

/// Produces OneTimeSignatures for messages and is deleted after use.
//#[derive(Serialize, Deserialize)]
struct EphemeralSubkey {
    pub pk: PublicKey,
    pub sk: SecretKey,

    /// The signature that authenticates PK.
    // It is the signature of the PK together with the batch number,
    // using an old style of signatures that we support for backwards
    // compatibility (thus the odd `codec:` name).
    pub pk_sig_old: Signature,

    /// The signature that authenticates PK, signed using the
    /// Hashable interface for domain separation (the Hashable object is either
    /// OTSSubkeyBatchID or OTSSubkeyOffsetID).
    pub pk_sig_new: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
