// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::*;
use crate::config;
use crate::data::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PaymentError {
    #[error("transaction cannot close account to its sender")]
    CannotCloseToSender,
    #[error("cannot spend from fee sink's address")]
    CannotSpendFromFeeSink,
    #[error("cannot close fee sink")]
    CannotCloseFeeSink,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

/// The fields used by payment transactions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentFields {
    #[serde(rename = "rcv", default, skip_serializing_if = "is_default")]
    pub receiver: basics::Address,
    #[serde(rename = "amt", default, skip_serializing_if = "is_default")]
    pub amount: basics::MicroAlgos,

    /// When `close_remainder_to` is set, the transaction is requesting that the account should be closed,
    /// and all remaining funds be transferred to this address.
    #[serde(rename = "close", default, skip_serializing_if = "is_default")]
    pub close_remainder_to: Option<basics::Address>,
}

impl PaymentFields {
    pub fn check_spender(
        &self,
        header: &Header,
        spec: &SpecialAddresses,
        proto: &config::ConsensusParams,
    ) -> Result<(), PaymentError> {
        if Some(&header.sender) == self.close_remainder_to.as_ref() {
            return Err(PaymentError::CannotCloseToSender);
        }

        // the fee sink account may only spend to the rewards pool
        if header.sender == spec.fee_sink {
            if self.receiver != spec.rewards_pool {
                return Err(PaymentError::CannotSpendFromFeeSink);
            } else if self.close_remainder_to.is_some() {
                return Err(PaymentError::CannotCloseFeeSink);
            }
        }
        Ok(())
    }
}
