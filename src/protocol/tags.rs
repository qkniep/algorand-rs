// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

/// Tag represents a message type identifier.  Messages have a Tag field. Handlers can register to a given Tag.
/// e.g., the agreement service can register to handle agreements with the Agreement tag.
type Tag = &'static str;

// Tags, in lexicographic sort order of tag values to avoid duplicates.
// These tags must not contain a comma character because lists of tags
// are encoded using a comma separator (see network/msgOfInterest.go).
// The tags must be 2 bytes long.
const UNKNOWN_MSG_TAG: Tag = "??";
const AGREEMENT_VOTE_TAG: Tag = "AV";
const COMPACT_CERT_SIG_TAG: Tag = "CS";
const MSG_OF_INTEREST_TAG: Tag = "MI";
const MSG_DIGEST_SKIP_TAG: Tag = "MS";
const NET_PRIO_RESPONSE_TAG: Tag = "NP";
const PING_TAG: Tag = "pi";
const PING_REPLY_TAG: Tag = "pj";
const PROPOSAL_PAYLOAD_TAG: Tag = "PP";
const TOPIC_MSG_RESP_TAG: Tag = "TS";
const TXN_TAG: Tag = "TX";
const UNI_CATCHUP_REQ_TAG: Tag = "UC"; // Replaced by uni_ens_block_req_tag. Only for backward compatibility.
const UNI_ENS_BLOCK_REQ_TAG: Tag = "UE";
//uni_ens_block_res_tag  Tag = "US" was used for wsfetcherservice
//uni_catchup_res_tag   Tag = "UT" was used for wsfetcherservice
const VOTE_BUNDLE_TAG: Tag = "VB";
