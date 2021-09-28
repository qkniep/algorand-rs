// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use crate::crypto;

/// Maximum number of arguments to a LogicSig.
const EVAL_MAX_ARGS: usize = 255;

/// LogicSig contains logic for validating a transaction.
///   - it is signed by an account, allowing delegation of operations, or
///   - defines a contract account
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicSig {
    /// Logic signed by Sig or Msig, OR hashed to be the Address of an account.
    pub logic: Vec<u8>,

    pub sig: crypto::Signature,
    pub msig: crypto::MultisigSignature,

    /// Args are not signed, but checked by Logic
    pub args: Vec<Vec<u8>>,
}

impl LogicSig {
    /// Returns true iff there is no content in this LogicSig.
    pub fn is_empty(&self) -> bool {
        self.logic.is_empty()
    }

    /// Len returns the length of Logic plus the length of the Args
    /// This is limited by config.ConsensusParams.LogicSigMaxSize
    pub fn len(&self) -> usize {
        self.args
            .iter()
            .fold(self.logic.len(), |sum, arg| sum + arg.len())
    }
}
