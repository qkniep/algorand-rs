// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod codec;
mod consensus;
mod hash;
mod tags;
mod txtype;

use serde::{Deserialize, Serialize};

pub use codec::*;
pub use consensus::*;
pub use hash::*;
pub use tags::*;
pub use txtype::*;

pub type NetworkID = &'static str;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactCertType {
    /// Initial compact cert setup, using Ed25519 ephemeral-key signatures and SHA512/256 hashes.
    Basic,
}

pub const NUM_COMPACT_CERT_TYPES: usize = 1;
