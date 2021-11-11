// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryInto;

use lazy_static::lazy_static;
use rand::{rngs::OsRng, RngCore};
use sled::Db;
use thiserror::Error;

use crate::config;
use crate::crypto;
use crate::data::*;
use crate::protocol;

lazy_static! {
    static ref KEY_STORE: Db = sled::open("keystore.db").unwrap();
}

/// Encapsulates a set of secrets which controls some store of money.
///
/// A `Root` is authorized to spend money and create `Participation`s
/// for which this account is the parent.
///
/// It handles persistence and secure deletion of secrets.
pub struct Root {
    pub kp: crypto::Keypair,
}

/// Encapsulates a set of secrets which allows a root to participate in consensus.
/// All such accounts are associated with a `parent` root account
/// (although this parent account may not be resident on this machine).
///
/// `Participation`s are allowed to vote on a user's behalf for some range of rounds.
/// After this range, all remaining secrets are destroyed.
///
/// For correctness, all `Root`s should have no more than one `Participation` globally active at any time.
/// If this condition is violated, the Root may equivocate.
/// (Algorand tolerates a limited fraction of misbehaving accounts.)
pub struct Participation {
    pub parent: basics::Address,

    pub vrf: crypto::VrfKeypair,
    pub voting: crypto::OTSSecrets,

    // The first and last rounds for which these participation keys are valid, respectively.
    // When `last_valid` has concluded, this set of secrets is destroyed.
    pub first_valid: basics::Round,
    pub last_valid: basics::Round,

    pub key_dilution: u64,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("did not find a matching object in storage")]
    NotFound,
    #[error("invalid round interval ({0}-{1})")]
    InvalidRoundInterval(basics::Round, basics::Round),
    #[error("failed to access account storage")]
    StorageError(#[from] sled::Error),
    #[error("failed to decode data type")]
    DecodeError(#[from] rmp_serde::decode::Error),
}

impl Root {
    /// Generate new account from system's source of randomness.
    pub fn generate() -> Result<Root, Error> {
        let mut seed = [0; 32];
        let mut rng = OsRng {};
        rng.fill_bytes(&mut seed);
        Root::import(seed)
    }

    /// Instantiate a key based on the given seed.
    fn import(seed: [u8; 32]) -> Result<Root, Error> {
        let kp = crypto::Keypair::from_bytes(&seed).unwrap();
        let raw = protocol::encode(&kp);

        KEY_STORE.insert("root", raw)?;
        KEY_STORE.flush()?;

        Ok(Root { kp })
    }

    /// Restores a Root from a database handle.
    pub fn restore() -> Result<Root, Error> {
        let res = KEY_STORE.get("root")?;
        if res.is_none() {
            return Err(Error::NotFound);
        }

        let kp = protocol::decode(&res.unwrap())?;

        Ok(Root { kp })
    }

    /// Secrets returns the signing secrets associated with the Root account.
    pub fn secrets(&self) -> &crypto::Keypair {
        &self.kp
    }

    /// Address returns the address associated with the Root account.
    pub fn address(&self) -> basics::Address {
        basics::Address(self.kp.public.to_bytes())
    }
}

impl Participation {
    /// Returns the first and last rounds for which this participation account is valid.
    pub fn valid_interval(&self) -> (basics::Round, basics::Round) {
        (self.first_valid, self.last_valid)
    }

    /// Returns the root account under which this participation account is registered.
    pub fn address(&self) -> basics::Address {
        self.parent
    }

    /// Returns true iff the partkey is valid at all within the range of rounds (inclusive)
    pub fn overlaps_interval(&self, first: basics::Round, last: basics::Round) -> bool {
        if last < first {
            // TODO log panic?
            panic!("round interval should be ordered (was {}-{})", first, last);
        }
        last >= self.first_valid && first <= self.last_valid
    }

    /// Returns the VRF keypair associated with this Participation account.
    pub fn vrf_keypair(&self) -> &crypto::VrfKeypair {
        &self.vrf
    }

    /// Returns the voting secrets associated with this Participation account.
    pub fn voting_keypair(&self) -> &crypto::OTSSecrets {
        &self.voting
    }

    /*
    // VotingSigner returns the voting secrets associated with this Participation account,
    // together with the KeyDilution value.
    pub fn voting_signer() -> PublicKey {
        return crypto.OneTimeSigner{
            OneTimeSignatureSecrets: part.Voting,
            OptionalKeyDilution:     part.KeyDilution,
        }
    }
    */

    /// Returns a transaction object for registering a `Participation` with its parent.
    pub fn generate_registration_transaction(
        &self,
        fee: basics::MicroAlgos,
        first_valid: basics::Round,
        last_valid: basics::Round,
        lease: [u8; 32],
    ) -> transactions::Transaction {
        transactions::Transaction {
            header: transactions::Header {
                sender: self.parent,
                fee,
                first_valid,
                last_valid,
                lease,
                ..transactions::Header::default()
            },
            fields: transactions::TxFields::Keyreg(transactions::KeyregFields {
                vote_pk: self.voting.verifier,
                selection_pk: self.vrf.public(),
                vote_first: self.first_valid,
                vote_last: self.last_valid,
                vote_key_dilution: self.key_dilution,
                nonparticipation: false,
            }),
        }
    }

    pub fn restore() -> Result<Self, Error> {
        let raw_parent = KEY_STORE.get("part-parent")?;
        let raw_vrf = KEY_STORE.get("part-vrf")?;
        let raw_voting = KEY_STORE.get("part-voting")?;
        let raw_first_valid = KEY_STORE.get("part-first_valid")?;
        let raw_last_valid = KEY_STORE.get("part-last_valid")?;
        let raw_key_dilution = KEY_STORE.get("part-key_dilution")?;

        let parent = raw_parent.unwrap().as_ref().try_into().unwrap();
        let vrf = protocol::decode(&raw_vrf.unwrap())?;
        let voting = protocol::decode(&raw_voting.unwrap())?;
        let first_valid = u64::from_be_bytes(raw_first_valid.unwrap().as_ref().try_into().unwrap());
        let last_valid = u64::from_be_bytes(raw_last_valid.unwrap().as_ref().try_into().unwrap());
        let key_dilution =
            u64::from_be_bytes(raw_key_dilution.unwrap().as_ref().try_into().unwrap());

        Ok(Self {
            parent: basics::Address(parent),
            vrf,
            voting,
            first_valid: basics::Round(first_valid),
            last_valid: basics::Round(last_valid),
            key_dilution,
        })
    }

    /// Securely deletes ephemeral keys for rounds strictly older than the given round.
    pub fn delete_old_keys(
        &mut self,
        current: basics::Round,
        proto: &config::ConsensusParams,
    ) -> Result<(), Error> {
        let mut key_dilution = self.key_dilution;
        if key_dilution == 0 {
            key_dilution = proto.default_key_dilution;
        }

        self.voting
            .delete_before(current.ots_id(key_dilution), key_dilution);
        let voting = self.voting.snapshot();
        let voting_enc = protocol::encode(&voting);
        KEY_STORE.insert("part-voting", voting_enc)?;
        KEY_STORE.flush()?;
        Ok(())
    }

    /// Writes a new parent address to the partkey database.
    pub fn persist_new_parent(&self) -> Result<(), Error> {
        KEY_STORE.insert("part-parent", &self.parent.0[..])?;
        KEY_STORE.flush()?;
        Ok(())
    }

    /// Initializes the passed database with participation keys.
    pub fn fill_db_with_participation_keys(
        parent: basics::Address,
        first_valid: basics::Round,
        last_valid: basics::Round,
        key_dilution: u64,
    ) -> Result<Participation, Error> {
        if last_valid < first_valid {
            return Err(Error::InvalidRoundInterval(first_valid, last_valid));
        }

        // Compute how many distinct participation keys we should generate
        let first_id = first_valid.ots_id(key_dilution);
        let last_id = last_valid.ots_id(key_dilution);
        let num_batches = last_id.batch - first_id.batch + 1;

        // Generate them
        let voting = crypto::OTSSecrets::generate(first_id.batch, num_batches);

        // Also generate a new VRF key, which lives in the participation keys db
        let mut seed = [0; 32];
        let mut rng = OsRng {};
        rng.fill_bytes(&mut seed);
        let vrf = crypto::VrfKeypair::from_seed(seed);

        // Construct the Participation containing these keys to be persisted
        let part = Participation {
            parent,
            vrf,
            voting,
            first_valid,
            last_valid,
            key_dilution,
        };
        // Persist the Participation into the database
        // TODO pass Error up
        part.persist().unwrap();
        Ok(part)
    }

    /// Persist writes a Participation out to a database on the disk
    pub fn persist(&self) -> Result<(), Error> {
        let vrf_enc = protocol::encode(&self.vrf);
        let voting = self.voting.snapshot();
        let voting_enc = protocol::encode(&voting);

        KEY_STORE.insert("part-parent", &self.parent.0[..])?;
        KEY_STORE.insert("part-vrf", vrf_enc)?;
        KEY_STORE.insert("part-voting", voting_enc)?;
        KEY_STORE.insert("part-first_valid", &self.first_valid.0.to_be_bytes()[..])?;
        KEY_STORE.insert("part-last_valid", &self.last_valid.0.to_be_bytes()[..])?;
        KEY_STORE.insert("part-key_dilution", &self.key_dilution.to_be_bytes()[..])?;
        KEY_STORE.flush()?;

        Ok(())
    }

    /*
    /// Called when loading participation keys.
    /// Calls through to the migration helper and returns the result.
    pub fn Migrate(part_db: &Db) error {
        return part_db.Atomic(func(ctx context.Context, tx *sql.Tx) error {
            return partMigrate(tx)
        })
    }
    */
}
