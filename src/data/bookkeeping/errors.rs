// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use thiserror::Error;

use crate::crypto::CryptoHash;
use crate::data::basics;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum InvalidBlock {
    /// Current round is outside of the transaction's validity window.
    #[error("round {round} outside valid range of {first_valid}-{last_valid}")]
    Dead {
        round: basics::Round,
        first_valid: basics::Round,
        last_valid: basics::Round,
    },

    #[error("block is for round {0}, expected round {1}")]
    WrongRound(basics::Round, basics::Round),
    #[error("block is following block with hash {0}, expected prev to be {1}")]
    WrongBranch(CryptoHash, CryptoHash),
    #[error("invalid upgrade state")]
    WrongUpgradeState,
    #[error("bad timestamp: current {0} < previous {1}")]
    BadEarlyTimestamp(u64, u64),
    #[error("bad timestamp: current {0} > previous {1} + max increment {2}")]
    BadLateTimestamp(u64, u64, u64),
    #[error("genesis ID missing")]
    MissingGenesisID,
    #[error("genesis ID mismatch {0}, prev block had {1}")]
    GenesisIDMismatch(String, String),
    #[error("genesis hash missing")]
    MissingGenesisHash,
    #[error("genesis hash mismatch {0}, prev block had {1}")]
    GenesisHashMismatch(CryptoHash, CryptoHash),
    #[error("genesis hash not supported")]
    GenesisHashNotSupported,

    // Errors that can happen in decode_signed_tx()
    #[error("genesis ID not empty")]
    NonEmptyGenesisID,
    #[error("genesis hash not empty")]
    NonEmptyGenesisHash,
    #[error("has_genesis_hash is redundant because require_genesis_hash is also set")]
    RedundantHasGenesisHash,

    // Error that can happen in apply_upgrade_vote()
    #[error("new proposal during existing proposal")]
    CompetingProposal,
    #[error("proposed protocol version %s too long")]
    VersionStringTooLong(usize, u32),
    #[error("proposed upgrade delay {0} out of permissible range [{1}, {2}]")]
    DelayOutOfRange(u64, u64, u64),
    #[error("upgrade delay non-zero but not proposing")]
    NonZeroDelayWithoutProposal,
    #[error("approval without an active proposal")]
    ApprovalNoneActive,
    #[error("approval after vote deadline")]
    ApprovalAfterDeadline(basics::Round, basics::Round),
}
