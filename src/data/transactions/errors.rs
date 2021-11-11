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

    // Functionality not supported
    #[error("asset transactions not supported")]
    AssetTxsNotSupported,
    #[error("application transactions not supported")]
    AppTxsNotSupported,
    #[error("compact certs not supported")]
    CompactcertTxsNotSupported,
    #[error("transaction leases are not yet supported")]
    LeasesNotSupported,
    #[error("transaction groups are not yet supported")]
    GroupsNotSupported,
    #[error("rekeying is not yet supported")]
    RekeyingNotSupported,

    #[error("tx has fee of {0} which is less than min ({1})")]
    FeeLessThanMin(basics::MicroAlgos, basics::MicroAlgos),
    #[error("transaction sender not set (set to zero)")]
    ZeroSender,

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

    // Keyreg - variant specific errors
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

    // AppCall - variant specific errors
    #[error("programs may only be specified during application creation or update")]
    ChangeProgramWithoutUpdate,
    #[error("local and global state schemas are immutable")]
    ChangeAppStateSchema,
    #[error("number of extra program pages is immutable")]
    ChangeExtraProgramPages,
    #[error("too many application args {0}, max is {1}")]
    TooManyAppArgs(usize, u32),
    #[error("application args total length too long {0} bytes, max is {1} bytes")]
    AppArgsTotalTooLong(usize, u32),
    #[error("accounts list too long {0}, max is {1}")]
    AccountsTooLong(usize, u32),
    #[error("foreign apps list too long {0}, max is {1}")]
    ForeignAppTooLong(usize, u32),
    #[error("foreign assets list too long {0}, max is {1}")]
    ForeignAssetsTooLong(usize, u32),
    #[error("too many references {0}, max is {1}")]
    TooManyReferences(usize, u32),
    #[error("too many extra program pages {0}, max is {1}")]
    TooManyExtraProgramPages(u32, u32),
    #[error("approval program too long {0} bytes, max is {1} bytes")]
    ApprovalProgramTooLong(usize, u32),
    #[error("clear state program too long {0} bytes, max is {1} bytes")]
    ClearStateProgramTooLong(usize, u32),
    #[error("app programs too long {0} bytes, max total is {1} bytes")]
    AppProgramsTooLong(usize, u32),
    #[error("local state schema too large {0}, max is {1}")]
    LocalStateSchemaTooLarge(u64, u64),
    #[error("global state schema too large {0}, max is {1}")]
    GlobalStateSchemaTooLarge(u64, u64),

    // CompactCert - variant specific errors
    #[error("sender must be the compact cert sender")]
    CCInvalidSender,
    #[error("fee must be zero")]
    CCNonZeroFee,
    #[error("note must be empty")]
    CCNonEmptyNote,
    #[error("group must be zero")]
    CCNonZeroGroup,
    #[error("rekey must be zero")]
    CCNonZeroRekey,
    #[error("lease must be zero")]
    CCNonZeroLease,

    #[error("an unknown error occurred")]
    Unknown,

    #[error("invalid payment transaction")]
    InvalidPayment(#[from] payment::PaymentError),
}
