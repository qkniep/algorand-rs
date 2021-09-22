// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

/// Domain separation prefix for an object type that might be hashed.
/// This ensures, for example, the hash of a transaction will never collide with the hash of a vote.
pub type HashID = &'static str;

// Hash IDs for specific object types, in lexicographic order.
// Hash IDs must be PREFIX-FREE (i.e. no hash ID is a prefix of another)!
pub const APP_INDEX: HashID = "appID";
pub const AUCTION_BID: HashID = "aB";
pub const AUCTION_DEPOSIT: HashID = "aD";
pub const AUCTION_OUTCOMES: HashID = "aO";
pub const AUCTION_PARAMS: HashID = "aP";
pub const AUCTION_SETTLEMENT: HashID = "aS";

pub const COMPACT_CERT_COIN: HashID = "ccc";
pub const COMPACT_CERT_PART: HashID = "ccp";
pub const COMPACT_CERT_SIG: HashID = "ccs";

pub const AGREEMENT_SELECTOR: HashID = "AS";
pub const BLOCK_HEADER: HashID = "BH";
pub const BALANCE_RECORD: HashID = "BR";
pub const CREDENTIAL: HashID = "CR";
pub const GENESIS: HashID = "GE";
pub const MERKLE_ARRAY_NODE: HashID = "MA";
pub const MESSAGE: HashID = "MX";
pub const NET_PRIO_RESPONSE: HashID = "NPR";
pub const ONE_TIME_SIG_KEY1: HashID = "OT1";
pub const ONE_TIME_SIG_KEY2: HashID = "OT2";
pub const PAYSET_FLAT: HashID = "PF";
pub const PAYLOAD: HashID = "PL";
pub const PROGRAM: HashID = "Program";
pub const PROGRAM_DATA: HashID = "prog_data";
pub const PROPOSER_SEED: HashID = "PS";
pub const SEED: HashID = "SD";
pub const SPECIAL_ADDR: HashID = "special_addr";
pub const SIGNED_TXN_IN_BLOCK: HashID = "STIB";
pub const TEST_HASHABLE: HashID = "TE";
pub const TX_GROUP: HashID = "TG";
pub const TXN_MERKLE_LEAF: HashID = "TL";
pub const TRANSACTION: HashID = "TX";
pub const VOTE: HashID = "VO";
