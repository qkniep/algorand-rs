// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fmt;

use crate::crypto::CryptoHash;
use crate::data::basics;

/// Defines error types which could be returned from the method `well_formed`.
#[derive(Debug, PartialEq, Eq)]
pub enum InvalidTx {
    /// Current round is outside of the transaction's validity window.
    Dead {
        round: basics::Round,
        first_valid: basics::Round,
        last_valid: basics::Round,
    },
    GenesisIdMismatch(String, String),
    GenesisHashMismatch(CryptoHash, CryptoHash),
    GenesisHashMissing,
    GenesisHashNotAllowed,

    KeyregFirstVotingRoundGreaterThanLastVotingRound,
    KeyregNonCoherentVotingKeys,
    KeyregOfflineTransactionHasVotingRounds,
    KeyregUnsupportedSwitchToNonParticipating,
    KeyregGoingOnlineWithNonParticipating,
    KeyregGoingOnlineWithZeroVoteLast,
    KeyregGoingOnlineWithFirstVoteAfterLastValid,

    AssetTxsNotSupported,
    AppTxsNotSupported,
    ///
    /// Fee is lower than minimum.
    FeeLessThanMin(basics::MicroAlgos, basics::MicroAlgos),

    BadValidityRange(basics::Round, basics::Round),
    ExcessiveValidityRange(basics::Round, basics::Round),
    NoteTooBig(usize, usize),
    AssetNameTooBig(usize, usize),
    AssetUnitNameTooBig(usize, usize),
    AssetUrlTooBig(usize, usize),
    AssetDecimalsTooHigh(usize, usize),
    ZeroSender,
    LeasesNotSupported,
    GroupsNotSupported,
    RekeyingNotSupported,
}

impl fmt::Display for InvalidTx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dead{round, first_valid, last_valid} => write!(f, "round {} outside valid range of {}-{}", round.0, first_valid.0, last_valid.0),
            Self::GenesisIdMismatch(have, want) => write!(f, "provided genesis ID {} does not match, expected {}", have, want),
            Self::GenesisHashMismatch(have, want) => write!(f, "provided genesis hash {} does not match, expected {}", have, want),
            Self::GenesisHashMissing => write!(f, "genesis hash required but missing"),
            Self::GenesisHashNotAllowed => write!(f, "genesis hash is not allowed"),

            Self::KeyregFirstVotingRoundGreaterThanLastVotingRound => write!(f, "transaction first voting round need to be less than its last voting round"),
            Self::KeyregNonCoherentVotingKeys => write!(f, "the following transaction fields need to be clear/set together : votekey, selkey, votekd"),
            Self::KeyregOfflineTransactionHasVotingRounds => write!(f, "on going offline key registration transaction, the vote first and vote last fields should not be set"),
            Self::KeyregUnsupportedSwitchToNonParticipating => write!(f, "transaction tries to mark an account as nonparticipating, but that transaction is not supported"),
            Self::KeyregGoingOnlineWithNonParticipating => write!(f, "transaction tries to register keys to go online, but nonparticipatory flag is set"),
            Self::KeyregGoingOnlineWithZeroVoteLast => write!(f, "transaction tries to register keys to go online, but vote last is set to zero"),
            Self::KeyregGoingOnlineWithFirstVoteAfterLastValid => write!(f, "transaction tries to register keys to go online, but first voting round is beyond the round after last valid round"),

            Self::AssetTxsNotSupported => write!(f, "asset transactions not supported"),
            Self::AppTxsNotSupported => write!(f, "application transactions not supported"),
            Self::FeeLessThanMin(fee, min) => write!(f, "tx has fee of {} which is less than min ({})", fee, min),

            Self::BadValidityRange(first_valid, last_valid) => write!(f, "bad validty range of {}-{}", first_valid.0, last_valid.0),
            Self::ExcessiveValidityRange(first_valid, last_valid) => write!(f, "validity range {}-{} is too large", first_valid.0, last_valid.0),
            Self::NoteTooBig(have, want) => write!(f, "the provided note is too long {}, max is {}", have, want),
            Self::AssetNameTooBig(have, want) => write!(f, "the provided asset name is too long {}, max is {}", have, want),
            Self::AssetUnitNameTooBig(have, want) => write!(f, "the provided asset unit name is too long {}, max is {}", have, want),
            Self::AssetUrlTooBig(have, want) => write!(f, "the provided asset URL is too long {}, max is {}", have, want),
            Self::AssetDecimalsTooHigh(have, want) => write!(f, "the provided asset decimal precision is too hight {}, max is {}", have, want),
            Self::ZeroSender => write!(f, "transaction sender not set (set to zero)"),
            Self::LeasesNotSupported => write!(f, "transaction leases are not yet supported"),
            Self::GroupsNotSupported => write!(f, "transaction groups are not yet supported"),
            Self::RekeyingNotSupported => write!(f, "rekeying is not yet supported"),
        }
    }
}

impl std::error::Error for InvalidTx {}
