// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use num::bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{sortition, Membership, Selector};
use crate::{
    config,
    crypto::{self, hashable::Hashable},
    data::basics,
    protocol,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to verify VRF Proof: {0}")]
    VrfVerifyFailed(#[from] crypto::VrfError),
    #[error("Credential has weight 0")]
    ZeroWeight,
}

/// Credential which has not yet been authenticated.
pub struct UnauthenticatedCredential {
    //_struct struct{}        `codec:",omitempty,omitemptyarray"`
    proof: crypto::VrfProof,
}

/// A Credential represents a proof of committee membership.
///
/// The multiplicity of this membership is specified in the Credential's
/// weight. The VRF output hash (with the owner's address hashed in) is
/// also cached.
///
/// Upgrades: Whether or not domain separation is enabled is cached.
/// If this flag is set, this flag also includes original hashable credential.
pub struct Credential {
    //_struct struct{}      `codec:",omitempty,omitemptyarray"`
    weight: u64,
    vrf_out: crypto::CryptoHash,

    domain_separation_enabled: bool,
    hashable: Option<HashableCredential>,

    inner: UnauthenticatedCredential,
}

#[derive(Serialize, Deserialize)]
struct HashableCredential {
    //_struct struct{}         `codec:",omitempty,omitemptyarray"`
    #[serde(skip)]
    raw_out: crypto::VrfOutput,
    member: basics::Address,
    iter: u64,
}

impl UnauthenticatedCredential {
    /// Creates a new unauthenticated Credential given some selector.
    fn new(secrets: &crypto::VrfKeypair, sel: &impl Selector) -> Self {
        match secrets.prove(sel) {
            Ok(pf) => Self { proof: pf },
            Err(_) => panic!("Failed to construct a VRF proof: participation key may be corrupt"),
        }
    }

    /// Verify an unauthenticated Credential that was received from the network.
    ///
    /// Verify checks if the given credential is a valid proof of membership
    /// conditioned on the provided committee membership parameters.
    ///
    /// If it is, the returned Credential constitutes a proof of this fact.
    /// Otherwise, an error is returned.
    fn verify<S: Selector>(
        self,
        proto: config::ConsensusParams,
        mem: Membership<S>,
    ) -> Result<Credential, Error> {
        let selection_key = mem.record.data.selection_id.clone();
        let vrf_out = selection_key.verify(&self.proof, &mem.selector)?;

        let hashable = HashableCredential {
            raw_out: vrf_out.clone(),
            member: mem.record.addr,
            iter: 0,
        };

        // Also hash in the address. This is necessary to decorrelate the selection of different accounts that have the same VRF key.
        let h: crypto::CryptoHash;
        if proto.credential_domain_separation_enabled {
            h = crypto::hash_obj(&hashable);
        } else {
            h = crypto::hash(&[&vrf_out.0[..], &mem.record.addr.0[..]].concat());
        }

        let mut weight = 0;
        let user_money = mem.record.data.voting_stake();
        let expected_selection = mem.selector.committee_size(&proto);

        if mem.total_money < user_money {
            // TODO log panic
            panic!(
                "UnauthenticatedCredential::verify: total money = {}, but user money = {}",
                mem.total_money, user_money
            );
        } else if mem.total_money.0 == 0
            || expected_selection == 0
            || expected_selection > mem.total_money.0
        {
            panic!(
                "UnauthenticatedCredential::verify: mem.total_money {}, expected_selection {}",
                mem.total_money, expected_selection
            );
        } else if user_money.0 != 0 {
            weight = sortition::select(
                user_money.0,
                mem.total_money.0,
                expected_selection as f64,
                &h,
            );
        }

        if weight == 0 {
            return Err(Error::ZeroWeight);
        }

        let mut res = Credential {
            inner: self,
            vrf_out: h,
            weight,
            domain_separation_enabled: proto.credential_domain_separation_enabled,
            hashable: None,
        };
        if res.domain_separation_enabled {
            res.hashable = Some(hashable);
        }
        Ok(res)
    }
}

impl Credential {
    /// Selected returns whether this Credential was selected (i.e., if its weight is greater than zero).
    fn selected(&self) -> bool {
        self.weight > 0
    }

    /// Used for breaking ties when there are multiple proposals.
    /// People will vote for the proposal whose credential has the lowest lowest_output().
    ///
    /// We hash the credential and interpret the output as a bigint.
    /// For credentials with weight w > 1, we hash the credential w times (with
    /// different counter values) and use the lowest output.
    ///
    /// This is because a weight w credential is simulating being selected to be on the
    /// leader committee w times, so each of the w proposals would have a different hash,
    /// and the lowest would win.
    fn lowest_output(&mut self) -> BigInt {
        let mut lowest = BigInt::from(0);

        let h1 = &self.vrf_out;
        // It is important that i start at 1 rather than 0 because cred.Hashable
        // was already hashed with iter = 0 earlier (in UnauthenticatedCredential.Verify)
        // for determining the weight of the credential. A nonzero iter provides
        // domain separation between lowestOutput and UnauthenticatedCredential.Verify
        //
        // If we reused the iter = 0 hash output here it would be nonuniformly
        // distributed (because lowestOutput can only get called if weight > 0).
        // In particular if i starts at 0 then weight-1 credentials are at a
        // significant disadvantage because UnauthenticatedCredential.Verify
        // wants the hash to be large but tiebreaking between proposals wants
        // the hash to be small.
        for i in 1..self.weight {
            let h: crypto::CryptoHash;
            if self.domain_separation_enabled {
                self.hashable.as_mut().unwrap().iter = i;
                h = crypto::hash_obj(self.hashable.as_ref().unwrap());
            } else {
                let mut h2 = crypto::CryptoHash([0; crypto::HASH_LEN]);
                h2.0[..std::mem::size_of_val(&i)].copy_from_slice(&i.to_be_bytes());
                h = crypto::hash([&h1.0[..], &h2.0[..]].concat().as_slice());
            }

            if i == 1 {
                lowest = BigInt::from_bytes_be(Sign::Plus, &h.0);
            } else {
                let temp = BigInt::from_bytes_be(Sign::Plus, &h.0);
                if temp < lowest {
                    lowest = temp;
                }
            }
        }

        lowest
    }

    /// Gives the lowestOutput as a crypto::CryptoHash, which allows pretty-printing a proposal's lowest output.
    /// This function is only used for debugging.
    fn lowest_output_digest(&mut self) -> crypto::CryptoHash {
        let (_, lbytes) = self.lowest_output().to_bytes_be();
        let mut out = crypto::CryptoHash([0; crypto::HASH_LEN]);
        if lbytes.len() > crypto::HASH_LEN {
            panic!("Cred lowest output too long");
        }
        out.0[crypto::HASH_LEN - lbytes.len()..].copy_from_slice(&lbytes);
        out
    }

    /// Used for breaking ties when there are multiple proposals.
    /// Precondition: both credentials have nonzero weight
    // TODO implement this as regular PartialOrd, by copying Credential in lowest_output
    //      therefore not requiring mut reference, but only regular reference
    fn lt(&mut self, other: &mut Credential) -> bool {
        let i1 = self.lowest_output();
        let i2 = other.lowest_output();

        i1 < i2
    }
}

impl PartialEq for Credential {
    /// Equals compares the hash of two Credentials to determine equality and returns true if they're equal.
    fn eq(&self, other: &Credential) -> bool {
        self.vrf_out == other.vrf_out
    }
}

impl Hashable for HashableCredential {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::CREDENTIAL, protocol::encode(&self))
    }
}
