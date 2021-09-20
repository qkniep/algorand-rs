// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fmt;

/// A string that identifies a version of the consensus protocol.
pub type ConsensusVersion = &'static str;

/// A baseline version of the Algorand consensus protocol.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V0: ConsensusVersion = "v0";

/// Adds support for Genesis ID in transactions, but does not require it
/// (transactions missing a Genesis ID value are still allowed).
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V1: ConsensusVersion = "v1";

/// Fixes a bug in the agreement protocol where proposalValues fail to commit to the original period and sender of a block.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V2: ConsensusVersion = "v2";

/// Adds support for fine-grained ephemeral keys.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V3: ConsensusVersion = "v3";

/// Adds support for a min balance and a transaction that closes out an account.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V4: ConsensusVersion = "v4";

/// Sets MinTxnFee to 1000 and fixes a blance lookback bug.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V5: ConsensusVersion = "v5";

/// Adds support for explicit ephemeral-key parameters.
/// It is now deprecated.
pub const DEPRECATED_CONSENSUS_V6: ConsensusVersion = "v6";

/// Increases MaxBalLookback to 320 in preparation for the twin seeds change.
pub const CONSENSUS_V7: ConsensusVersion = "v7";

/// Uses the new parameters and seed derivation policy from the agreement protocol's security analysis.
pub const CONSENSUS_V8: ConsensusVersion = "v8";

/// Increases min balance to 100,000 microAlgos.
pub const CONSENSUS_V9: ConsensusVersion = "v9";

/// Introduces fast partition recovery.
pub const CONSENSUS_V10: ConsensusVersion = "v10";

/// Introduces efficient encoding of SignedTxn using SignedTxnInBlock.
pub const CONSENSUS_V11: ConsensusVersion = "v11";

/// Increases the maximum length of a version string.
pub const CONSENSUS_V12: ConsensusVersion = "v12";

/// Makes the consensus version a meaningful string.
pub const CONSENSUS_V13: ConsensusVersion =
    // Points to version of the Algorand spec as of May 21, 2019.
    "https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795";

/// Adds tracking of closing amounts in ApplyData, and enables genesis hash in transactions.
pub const CONSENSUS_V14: ConsensusVersion =
    "https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9";

/// Adds tracking of reward distributions in ApplyData.
pub const CONSENSUS_V15: ConsensusVersion =
    "https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622";

/// Fixes domain separation in Credentials and requires GenesisHash.
pub const CONSENSUS_V16: ConsensusVersion =
    "https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101";

/// Points to 'final' spec commit for 2019 june release.
pub const CONSENSUS_V17: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0";

/// Points to reward calculation spec commit.
pub const CONSENSUS_V18: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f";

/// Points to 'final' spec commit for 2019 nov release.
pub const CONSENSUS_V19: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c";

/// Points to adding the decimals field to assets.
pub const CONSENSUS_V20: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa";

/// Fixes a bug in credential.lowestOutput.
pub const CONSENSUS_V21: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b";

/// Allows tuning the upgrade delay.
pub const CONSENSUS_V22: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2";

/// Fixes lease behavior.
pub const CONSENSUS_V23: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f";

/// Include the applications, rekeying and teal v2.
pub const CONSENSUS_V24: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782";

/// Adds support for AssetCloseAmount in the ApplyData.
pub const CONSENSUS_V25: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466";

/// Adds support for TEAL 3, initial rewards calculation and merkle tree hash commitments.
pub const CONSENSUS_V26: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff";

/// Updates ApplyDelta.EvalDelta.LocalDeltas format.
pub const CONSENSUS_V27: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595";

/// Introduces new TEAL features, larger program size, fee pooling and longer asset max URL.
pub const CONSENSUS_V28: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a";

/// Fixes application update by using ExtraProgramPages in size calculations.
pub const CONSENSUS_V29: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1";

/// Introduces AVM 1.0 and TEAL 5, increases the app opt in limit to 50,
/// and allows costs to be pooled in grouped stateful transactions.
pub const CONSENSUS_V30: ConsensusVersion =
    "https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c";

/// Is a protocol that should not appear in any production
/// network, but is used to test features before they are released.
pub const CONSENSUS_FUTURE: ConsensusVersion = "future";

// !!! ********************* !!!
// !!! *** Please update ConsensusCurrentVersion when adding new protocol versions *** !!!
// !!! ********************* !!!

/// ConsensusCurrentVersion is the latest version and should be used when a specific version is not provided.
pub const CURRENT_CONSENSUS_VERSION: ConsensusVersion = CONSENSUS_V30;

/// UnsupportedConsensusProtocol is used to indicate that an unsupported protocol has been detected.
#[derive(Debug, Clone)]
struct UnsupportedConsensusProtocol(ConsensusVersion);

impl fmt::Display for UnsupportedConsensusProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Consensus protocol version not supported: {}", self.0)
    }
}
