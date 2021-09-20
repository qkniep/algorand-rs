// Copyright (C) 2021 qkniep <qkniep@qk-huawei>
// Distributed under terms of the MIT license.

/// Domain separation prefix for an object type that might be hashed.
/// This ensures, for example, the hash of a transaction will never collide with the hash of a vote.
pub type HashID = &'static str;

// Hash IDs for specific object types, in lexicographic order.
// Hash IDs must be PREFIX-FREE (i.e. no hash ID is a prefix of another)!
const APP_INDEX: HashID = "appID";
const AUCTION_BID: HashID = "aB";
const AUCTION_DEPOSIT: HashID = "aD";
const AUCTION_OUTCOMES: HashID = "aO";
const AUCTION_PARAMS: HashID = "aP";
const AUCTION_SETTLEMENT: HashID = "aS";

const COMPACT_CERT_COIN: HashID = "ccc";
const COMPACT_CERT_PART: HashID = "ccp";
const COMPACT_CERT_SIG: HashID = "ccs";

const AGREEMENT_SELECTOR: HashID = "AS";
const BLOCK_HEADER: HashID = "BH";
const BALANCE_RECORD: HashID = "BR";
const CREDENTIAL: HashID = "CR";
const GENESIS: HashID = "GE";
const MERKLE_ARRAY_NODE: HashID = "MA";
const MESSAGE: HashID = "MX";
const NET_PRIO_RESPONSE: HashID = "NPR";
const ONE_TIME_SIG_KEY1: HashID = "OT1";
const ONE_TIME_SIG_KEY2: HashID = "OT2";
const PAYSET_FLAT: HashID = "PF";
const PAYLOAD: HashID = "PL";
const PROGRAM: HashID = "Program";
const PROGRAM_DATA: HashID = "prog_data";
const PROPOSER_SEED: HashID = "PS";
const SEED: HashID = "SD";
const SPECIAL_ADDR: HashID = "special_addr";
const SIGNED_TXN_IN_BLOCK: HashID = "STIB";
const TEST_HASHABLE: HashID = "TE";
const TX_GROUP: HashID = "TG";
const TXN_MERKLE_LEAF: HashID = "TL";
const TRANSACTION: HashID = "TX";
const VOTE: HashID = "VO";
