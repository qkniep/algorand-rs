// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use super::*;
use crate::{crypto, data::basics};

/// Captures the fields used for key registration transactions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyregFields {
    pub vote_pk: crypto::OTSVerifier,
    pub selection_pk: crypto::VrfPublicKey,
    pub vote_first: basics::Round,
    pub vote_last: basics::Round,
    pub vote_key_dilution: u64,
    pub nonparticipation: bool,
}

impl KeyregFields {
    pub fn check_coherency(&self, header: &Header) -> Result<(), InvalidTx> {
        // ensure that the VoteLast is greater or equal to the VoteFirst
        if self.vote_first > self.vote_last {
            return Err(InvalidTx::KeyregFirstVotingRoundGreaterThanLastVotingRound);
        }

        // The trio of [VotePK, SelectionPK, VoteKeyDilution] needs to be all zeros or all non-zero for the transaction to be valid.
        if !((self.vote_pk == Default::default()
            && self.selection_pk == Default::default()
            && self.vote_key_dilution == 0)
            || (self.vote_pk != Default::default()
                && self.selection_pk != Default::default()
                && self.vote_key_dilution != 0))
        {
            return Err(InvalidTx::KeyregNonCoherentVotingKeys);
        }

        // if it's a going offline transaction
        if self.vote_key_dilution == 0 {
            // check that we don't have any VoteFirst/VoteLast fields.
            if self.vote_first != basics::Round(0) || self.vote_last != basics::Round(0) {
                return Err(InvalidTx::KeyregOfflineTransactionHasVotingRounds);
            }
        } else {
            // going online
            if self.vote_last == basics::Round(0) {
                return Err(InvalidTx::KeyregGoingOnlineWithZeroVoteLast);
            } else if self.vote_first.0 > header.last_valid.0 + 1 {
                return Err(InvalidTx::KeyregGoingOnlineWithFirstVoteAfterLastValid);
            }
        }

        return Ok(());
    }
}
