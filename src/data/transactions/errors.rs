// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use thiserror::Error;

use super::payment;
use crate::crypto::CryptoHash;
use crate::data::basics;

/// Defines error types which could be returned from the method `well_formed`.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum InvalidTx {
    /// Current round is outside of the transaction's validity window.
    #[error("round {round} outside valid range of {first_valid}-{last_valid}")]
    Dead {
        round: basics::Round,
        first_valid: basics::Round,
        last_valid: basics::Round,
    },
    #[error("provided genesis ID {0} does not match, expected {1}")]
    GenesisIdMismatch(String, String),
    #[error("provided genesis hash {0} does not match, expected {0}")]
    GenesisHashMismatch(CryptoHash, CryptoHash),
    #[error("genesis hash required but missing")]
    GenesisHashMissing,
    #[error("genesis hash is not allowed")]
    GenesisHashNotAllowed,

    #[error("transaction first voting round need to be less than its last voting round")]
    KeyregFirstVotingRoundGreaterThanLastVotingRound,
    #[error("following fields need to be clear/set together: votekey, selkey, votekd")]
    KeyregNonCoherentVotingKeys,
    #[error("on going offline key registration transaction, the vote first and vote last fields should not be set")]
    KeyregOfflineTransactionHasVotingRounds,
    #[error("transaction tries to mark an account as nonparticipating, but that transaction is not supported")]
    KeyregUnsupportedSwitchToNonParticipating,
    #[error("transaction tries to register keys to go online, but nonparticipatory flag is set")]
    KeyregGoingOnlineWithNonParticipating,
    #[error("transaction tries to register keys to go online, but vote last is set to zero")]
    KeyregGoingOnlineWithZeroVoteLast,
    #[error("transaction tries to register keys to go online, but first voting round is beyond the round after last valid round")]
    KeyregGoingOnlineWithFirstVoteAfterLastValid,

    #[error("asset transactions not supported")]
    AssetTxsNotSupported,
    #[error("application transactions not supported")]
    AppTxsNotSupported,
    #[error("compact certs not supported")]
    CompactcertTxsNotSupported,

    /// Fee is lower than minimum.
    #[error("tx has fee of {0} which is less than min ({1})")]
    FeeLessThanMin(basics::MicroAlgos, basics::MicroAlgos),

    #[error("bad validty range of {0}-{1}")]
    BadValidityRange(basics::Round, basics::Round),
    #[error("validity range {0}-{1} is too large")]
    ExcessiveValidityRange(basics::Round, basics::Round),
    #[error("the provided note is too long {0}, max is {1}")]
    NoteTooBig(usize, u32),
    #[error("the provided asset name is too long {0}, max is {1}")]
    AssetNameTooBig(usize, u32),
    #[error("the provided asset unit name is too long {0}, max is {1}")]
    AssetUnitNameTooBig(usize, u32),
    #[error("the provided asset URL is too long {0}, max is {1}")]
    AssetUrlTooBig(usize, u32),
    #[error("the provided asset decimal precision is too hight {0}, max is {1}")]
    AssetDecimalsTooHigh(u32, u32),

    #[error("transaction sender not set (set to zero)")]
    ZeroSender,

    #[error("transaction leases are not yet supported")]
    LeasesNotSupported,
    #[error("transaction groups are not yet supported")]
    GroupsNotSupported,
    #[error("rekeying is not yet supported")]
    RekeyingNotSupported,

    #[error("an unknown error occurred")]
    Unknown,

    #[error("invalid payment transaction")]
    InvalidPayment(#[from] payment::PaymentError),
}
