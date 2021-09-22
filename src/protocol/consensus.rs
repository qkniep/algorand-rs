// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use std::fmt;

// !!! *************************************************************************************** !!!
// !!! *** Please update CURRENT_CONSENSUS_VERSION below when adding new protocol versions *** !!!
// !!! *************************************************************************************** !!!

/// A string that identifies a version of the consensus protocol.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusVersion {
    /// A baseline version of the Algorand consensus protocol.
    /// It is now deprecated!
    DeprecatedV0, // "v0";

    /// Adds support for Genesis ID in transactions, but does not require it
    /// (transactions missing a Genesis ID value are still allowed).
    /// It is now deprecated!
    DeprecatedV1, // "v1";

    /// Fixes a bug in the agreement protocol where proposalValues fail to commit to the original period and sender of a block.
    /// It is now deprecated!
    DeprecatedV2, // "v2";

    /// Adds support for fine-grained ephemeral keys.
    /// It is now deprecated!
    DeprecatedV3, // "v3";

    /// Adds support for a min balance and a transaction that closes out an account.
    /// It is now deprecated!
    DeprecatedV4, // "v4";

    /// Sets MinTxnFee to 1000 and fixes a blance lookback bug.
    /// It is now deprecated!
    DeprecatedV5, // "v5";

    /// Adds support for explicit ephemeral-key parameters.
    /// It is now deprecated!
    DeprecatedV6, // "v6";

    /// Increases MaxBalLookback to 320 in preparation for the twin seeds change.
    V7, // "v7";

    /// Uses the new parameters and seed derivation policy from the agreement protocol's security analysis.
    V8, // "v8";

    /// Increases min balance to 100,000 microAlgos.
    V9, // "v9";

    /// Introduces fast partition recovery.
    V10, // "v10";

    /// Introduces efficient encoding of SignedTxn using SignedTxnInBlock.
    V11, // "v11";

    /// Increases the maximum length of a version string.
    V12, // "v12";

    /// Makes the consensus version a meaningful string.
    /// Points to version of the Algorand spec as of May 21, 2019.
    V13, // "https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795";

    /// Adds tracking of closing amounts in ApplyData, and enables genesis hash in transactions.
    V14, // "https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9";

    /// Adds tracking of reward distributions in ApplyData.
    V15, // "https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622";

    /// Fixes domain separation in Credentials and requires GenesisHash.
    V16, // "https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101";

    /// Points to 'final' spec commit for 2019 june release.
    V17, // "https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0";

    /// Points to reward calculation spec commit.
    V18, // "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f";

    /// Points to 'final' spec commit for 2019 nov release.
    V19, // "https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c";

    /// Points to adding the decimals field to assets.
    V20, // "https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa";

    /// Fixes a bug in credential.lowestOutput.
    V21, // "https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b";

    /// Allows tuning the upgrade delay.
    V22, // "https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2";

    /// Fixes lease behavior.
    V23, // "https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f";

    /// Include the applications, rekeying and teal v2.
    V24, // "https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782";

    /// Adds support for AssetCloseAmount in the ApplyData.
    V25, // "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466";

    /// Adds support for TEAL 3, initial rewards calculation and merkle tree hash commitments.
    V26, // "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff";

    /// Updates ApplyDelta.EvalDelta.LocalDeltas format.
    V27, // "https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595";

    /// Introduces new TEAL features, larger program size, fee pooling and longer asset max URL.
    V28, // "https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a";

    /// Fixes application update by using ExtraProgramPages in size calculations.
    V29, // "https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1";

    /// Introduces AVM 1.0 and TEAL 5, increases the app opt in limit to 50,
    /// and allows costs to be pooled in grouped stateful transactions.
    V30, // "https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c";

    /// Is a protocol that should not appear in any production
    /// network, but is used to test features before they are released.
    Future, // "future";
}

impl fmt::Display for ConsensusVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::DeprecatedV0 => "v0",
            Self::DeprecatedV1 => "v1",
            Self::DeprecatedV2 => "v2",
            Self::DeprecatedV3 => "v3",
            Self::DeprecatedV4 => "v4",
            Self::DeprecatedV5 => "v5",
            Self::DeprecatedV6 => "v6",
            Self::V7 => "v7",
            Self::V8 => "v8",
            Self::V9 => "v9",
            Self::V10 => "v10",
            Self::V11 => "v11",
            Self::V12 => "v12",
            Self::V13 => "https://github.com/algorand/spec/tree/0c8a9dc44d7368cc266d5407b79fb3311f4fc795",
            Self::V14 => "https://github.com/algorand/spec/tree/2526b6ae062b4fe5e163e06e41e1d9b9219135a9",
            Self::V15 => "https://github.com/algorand/spec/tree/a26ed78ed8f834e2b9ccb6eb7d3ee9f629a6e622",
            Self::V16 => "https://github.com/algorand/spec/tree/22726c9dcd12d9cddce4a8bd7e8ccaa707f74101",
            Self::V17 => "https://github.com/algorandfoundation/specs/tree/5615adc36bad610c7f165fa2967f4ecfa75125f0",
            Self::V18 => "https://github.com/algorandfoundation/specs/tree/6c6bd668be0ab14098e51b37e806c509f7b7e31f",
            Self::V19 => "https://github.com/algorandfoundation/specs/tree/0e196e82bfd6e327994bec373c4cc81bc878ef5c",
            Self::V20 => "https://github.com/algorandfoundation/specs/tree/4a9db6a25595c6fd097cf9cc137cc83027787eaa",
            Self::V21 => "https://github.com/algorandfoundation/specs/tree/8096e2df2da75c3339986317f9abe69d4fa86b4b",
            Self::V22 => "https://github.com/algorandfoundation/specs/tree/57016b942f6d97e6d4c0688b373bb0a2fc85a1a2",
            Self::V23 => "https://github.com/algorandfoundation/specs/tree/e5f565421d720c6f75cdd186f7098495caf9101f",
            Self::V24 => "https://github.com/algorandfoundation/specs/tree/3a83c4c743f8b17adfd73944b4319c25722a6782",
            Self::V25 => "https://github.com/algorandfoundation/specs/tree/bea19289bf41217d2c0af30522fa222ef1366466",
            Self::V26 => "https://github.com/algorandfoundation/specs/tree/ac2255d586c4474d4ebcf3809acccb59b7ef34ff",
            Self::V27 => "https://github.com/algorandfoundation/specs/tree/d050b3cade6d5c664df8bd729bf219f179812595",
            Self::V28 => "https://github.com/algorandfoundation/specs/tree/65b4ab3266c52c56a0fa7d591754887d68faad0a",
            Self::V29 => "https://github.com/algorandfoundation/specs/tree/abc54f79f9ad679d2d22f0fb9909fb005c16f8a1",
            Self::V30 => "https://github.com/algorandfoundation/specs/tree/bc36005dbd776e6d1eaf0c560619bb183215645c",
            Self::Future => "future"
        })
    }
}

/// ConsensusCurrentVersion is the latest version and should be used when a specific version is not provided.
pub const CURRENT_CONSENSUS_VERSION: ConsensusVersion = ConsensusVersion::V30;

/// UnsupportedConsensusProtocol is used to indicate that an unsupported protocol has been detected.
#[derive(Clone, Debug)]
struct UnsupportedConsensusProtocol(ConsensusVersion);

impl fmt::Display for UnsupportedConsensusProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "consensus protocol version not supported: {}", self.0)
    }
}

impl std::error::Error for UnsupportedConsensusProtocol {}
