// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fmt;

use super::*;
use crate::config;
use crate::data::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentError {
    CannotCloseToSender,
    CannotSpendFromFeeSink,
    CannotCloseFeeSink,
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotCloseToSender => {
                write!(f, "transaction cannot close account to its sender")
            }
            Self::CannotSpendFromFeeSink => write!(f, "cannot spend from fee sink's address"),
            Self::CannotCloseFeeSink => write!(f, "cannot close fee sink"),
        }
    }
}

impl std::error::Error for PaymentError {}

/// The fields used by payment transactions.
pub struct PaymentFields {
    pub receiver: basics::Address,
    pub amount: basics::MicroAlgos,

    /// When `close_remainder_to` is set, the transaction is requesting that the account should be closed,
    /// and all remaining funds be transferred to this address.
    pub close_remainder_to: Option<basics::Address>,
}

impl PaymentFields {
    fn check_spender(
        &self,
        header: Header,
        spec: SpecialAddresses,
        proto: config::ConsensusParams,
    ) -> Result<(), PaymentError> {
        if Some(header.sender) == self.close_remainder_to {
            return Err(PaymentError::CannotCloseToSender);
        }

        // the FeeSink account may only spend to the IncentivePool
        if header.sender == spec.fee_sink {
            if self.receiver != spec.rewards_pool {
                return Err(PaymentError::CannotSpendFromFeeSink);
            } else if self.close_remainder_to.is_some() {
                return Err(PaymentError::CannotCloseFeeSink);
            }
        }
        return Ok(());
    }
}
