// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

//use crate::compactcert;
use crate::crypto::hashable::*;
use crate::data::basics;
use crate::protocol;

/// Captures the fields used for compact cert transactions.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactCertFields {
    pub cert_round: basics::Round,
    pub cert_type: protocol::CompactCertType,
    //pub cert: compactcert::Cert,
}

/*
impl CompactCertFields {
    /// Empty returns whether the CompactCertFields are all zero,
    /// in the sense of being omitted in a msgpack encoding.
    fn (cc CompactCertFields) Empty() bool {
        if cc.CertRound != 0 {
            return false
        } else if !cc.Cert.SigCommit.IsZero() || cc.Cert.SignedWeight != 0 {
            return false
        } else if cc.Cert.SigProofs) != 0 || len(cc.Cert.PartProofs) != 0 {
            return false
        }
        if len(cc.Cert.Reveals) != 0 {
            return false
        }
        return true;
    }
}
*/

/// Is used to form a unique address that will send out compact certs.
struct SpecialAddr(pub String);

impl Hashable for SpecialAddr {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::SPECIAL_ADDR, self.0.as_bytes().to_vec())
    }
}

// CompactCertSender is the computed address for sending out compact certs.
lazy_static! {
    pub static ref COMPACT_CERT_SENDER: basics::Address =
        basics::Address::new(hash_obj(&SpecialAddr("CompactCertSender".to_owned())));
}
