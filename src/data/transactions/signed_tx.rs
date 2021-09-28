// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use super::*;
use crate::crypto::{self, hashable::*};
use crate::data::basics;
use crate::protocol;

/// Wraps a transaction and a signature.
/// It exposes a verify() method that verifies the signature and checks that the underlying transaction is well-formed.
// TODO: update this documentation now that there's multisig
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTx {
    pub sig: crypto::Signature,
    pub msig: Option<crypto::MultisigSignature>,
    pub lsig: Option<LogicSig>,
    pub tx: Transaction,
    pub auth_addr: basics::Address,
}

/// How a signed transaction is encoded in a block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTxInBlock {
    pub tx: SignedTxWithAD,

    pub has_genesis_id: bool,
    pub has_genesis_hash: bool,
}

/// A (decoded) SignedTx with associated ApplyData.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTxWithAD {
    pub tx: SignedTx,
    pub ad: ApplyData,
}

impl SignedTx {
    /// ID returns the TxID (i.e., hash) of the underlying transaction.
    pub fn id(&self) -> TxID {
        self.tx.id()
    }

    /// Returns the length in bytes of the encoded transaction
    pub fn get_encoded_length(&self) -> usize {
        protocol::encode(self).len()
    }

    /// Returns the address against which the signature/msig/lsig should be checked, or so the SignedTx claims.
    /// This is just s.AuthAddr or, if s.auth_addr is zero, s.tx.sender.
    /// It's provided as a convenience method.
    pub fn authorizer(&self) -> basics::Address {
        if self.auth_addr.is_zero() {
            self.tx.header().sender
        } else {
            self.auth_addr
        }
    }
}

impl SignedTxInBlock {
    /// Returns the length in bytes of the encoded transaction.
    pub fn get_encoded_length(&self) -> usize {
        protocol::encode(self).len()
    }
}

impl Hashable for SignedTxInBlock {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        //(protocol::SIGNED_TXN_IN_BLOCK, protocol::encode(s))
        (protocol::SIGNED_TXN_IN_BLOCK, Vec::new())
    }
}

/// Takes an array SignedTx and returns the same as SignedTxnWithAD.
/// Each TXs ApplyData is the default empty state.
pub fn wrap_signed_txs_with_ad(tx_group: &[SignedTx]) -> Vec<SignedTxWithAD> {
    tx_group
        .iter()
        .map(|tx| SignedTxWithAD {
            tx: tx.clone(),
            ad: Default::default(),
        })
        .collect()
}

/// Computes the amount of fee credit that can be spent on inner TXs because it was more than required.
pub fn fee_credit(tx_group: &[SignedTx], min_fee: u64) -> Result<u64, ()> {
    let mut min_fee_count = 0;
    let mut fees_paid = 0_u64;
    for stxn in tx_group {
        if let Transaction::CompactCert(_, _) = stxn.tx {
            min_fee_count += 1;
        }
        fees_paid = fees_paid.saturating_add(stxn.tx.header().fee.0);
    }
    match min_fee.checked_mul(min_fee_count) {
        //return 0, fmt.Errorf("txgroup fee requirement overflow")
        None => Err(()),
        Some(fees_needed) => {
            if fees_paid < fees_needed {
                // fees_paid may have saturated; that's ok.
                // Since we know fee_needed did not overflow, simple comparison tells us fees_paid was enough.
                //return 0, fmt.Errorf("txgroup had %d in fees, which is less than the minimum %d * %d", fees_paid, min_fee_count, min_fee)
                Err(())
            } else {
                // Now, if fees_paid *did* saturate, you will not get "credit" for
                // all those fees while executing AVM code that might create transactions.
                // But you'll get the max u64 - good luck spending it.
                Ok(fees_paid - fees_needed)
            }
        }
    }
}
