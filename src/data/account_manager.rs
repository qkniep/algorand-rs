// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use tracing::warn;

use crate::config;
use crate::crypto;
use crate::data::{account, basics, bookkeeping};
use crate::protocol;

/// A ParticipationKeyIdentity defines the parameters that makes a pariticpation key unique.
#[derive(Hash, PartialEq, Eq)]
struct ParticipationKeyIdentity {
	pub address: basics::Address, // the address this participation key is used to vote for.

	/// FirstValid and LastValid are inclusive.
	pub first_valid: basics::Round,
	pub last_valid: basics::Round,

	pub vote_id:     crypto::OTSVerifier,
	pub selection_id: crypto::VrfPublicKey,
}

/// AccountManager loads and manages accounts for the node
#[derive(Default)]
struct AccountManager {
	mu: Mutex<()>,

	part_keys: HashMap<ParticipationKeyIdentity, account::Participation>,

	/// Keeps track of accounts for which we've sent AccountRegistered telemetry events.
	registered_accounts: HashSet<String>,
}

impl AccountManager {
    /// Returns a list of Participation accounts.
    pub fn keys(&self, round: basics::Round) -> Vec<&account::Participation> {
        let _guard = self.mu.lock();

        self.part_keys.values().filter(|p| {
            p.overlaps_interval(round, round)
        }).collect()
    }

    /// Returns true if we have any Participation keys valid for the specified round range (inclusive).
    pub fn has_live_keys(&self, from: basics::Round, to: basics::Round) -> bool {
        let _guard = self.mu.lock();

        self.part_keys.values().any(|p| {
            p.overlaps_interval(from, to)
        })
    }

    /// Adds a new `account::Participation` to be managed.
    /// The return value indicates if the key has been added (true) or if this is a duplicate key (false).
    pub fn add_participation(&mut self, participation: account::Participation) -> bool {
        let _guard = self.mu.lock();

        let address = participation.address();

        let (first_valid, last_valid) = participation.valid_interval();
        let partkey_id = ParticipationKeyIdentity {
            address,
            first_valid,
            last_valid,
            vote_id:      participation.voting.verifier,
            selection_id: participation.vrf.public(),
        };

        // Check if we already have participation keys for this address in this interval
        if self.part_keys.contains_key(&partkey_id) {
            return false
        }

        self.part_keys.insert(partkey_id, participation);

        let address_str = address.to_string();
        /*manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.PartKeyRegisteredEvent, telemetryspec.PartKeyRegisteredEventDetails{
            Address:    addressString,
            FirstValid: uint64(first),
            LastValid:  uint64(last),
        })*/

        if !self.registered_accounts.contains(&address_str) {
            self.registered_accounts.insert(address_str);

            /*manager.log.EventWithDetails(telemetryspec.Accounts, telemetryspec.AccountRegisteredEvent, telemetryspec.AccountRegisteredEventDetails{
                Address: addressString,
            })*/
        }

        true
    }

    /// Deletes all accounts' ephemeral keys strictly older than the next round needed for each account.
    pub fn delete_old_keys(&mut self, latest_header: bookkeeping::BlockHeader, cc_sigs: HashMap<basics::Address, basics::Round>, agreement_proto: config::ConsensusParams) {
        let _guard = self.mu.lock();
        let latest_proto = config::CONSENSUS.0[&latest_header.current_protocol];

        for part in self.part_keys.values() {
            // We need a key for round r+1 for agreement.
            let next_round = latest_header.round + 1;

            if latest_header.compact_cert[protocol::CompactCertType::Basic].compactcert_next_round > 0 {
                // We need a key for the next compact cert round.
                // This would be CompactCertNextRound+1 (+1 because compact
                // cert code uses the next round's ephemeral key), except
                // if we already used that key to produce a signature (as
                // reported in ccSigs).
                let mut next_cc = latest_header.compact_cert[protocol::CompactCertType::Basic].compactcert_next_round + 1;
                if cc_sig.get(part.parent).unwrap() >= next_cc {
                    next_cc = cc_sigs.get(part.parent).unwrap() + basics::Round(latest_proto.compactcert_rounds + 1);
                }

                if next_cc < next_round {
                    next_round = next_cc;
                }
            }

            // we pre-create the reported error string here, so that we won't need to have the participation key object if error is detected.
            let (first, last) = part.valid_interval();
            if let Err(err) = part.delete_old_keys(next_round, agreement_proto) {
                let err_str = format!("AccountManager.DeleteOldKeys(): key for {} ({}-{}), next_round {}", part.address().to_string(), first, last, next_round)

                warn!("{}: {}", err_str, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn it_works() {
	}
}
