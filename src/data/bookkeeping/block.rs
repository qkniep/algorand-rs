// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::TxMerkleArray;
use crate::config;
use crate::crypto::{self, hashable::*};
use crate::data::{basics, committee, transactions};
use crate::protocol;

// TODO Error type
// TODO ConsensusVersion and String...

/// A Block contains the Payset and metadata corresponding to a given Round.
#[derive(Clone, Default)]
pub struct Block {
    pub header: BlockHeader,
    pub payset: transactions::Payset,
}

/// Represents the metadata and commitments to the state of a Block.
/// The Algorand Ledger may be defined minimally as a cryptographically authenticated series of `BlockHeader` objects.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BlockHeader {
    pub round: basics::Round,

    /// The hash of the previous block
    pub branch: CryptoHash,

    /// Sortition seed
    pub seed: committee::Seed,

    /// Root hash that authenticates the set of transactions appearing in the block.
    /// Computed based on the `PaysetCommitType` specified in the block's consensus protocol.
    pub tx_root: CryptoHash,

    /// TimeStamp in seconds since epoch
    pub timestamp: u64,

    /// Genesis ID to which this block belongs.
    pub genesis_id: String,

    /// Genesis hash to which this block belongs.
    pub genesis_hash: CryptoHash,

    /// Rewards.
    ///
    /// When a block is applied, some amount of rewards are accrued to
    /// every account with AccountData.Status=/=NotParticipating.  The
    /// amount is (thisBlock.RewardsLevel-prevBlock.RewardsLevel) of
    /// MicroAlgos for every whole config.Protocol.RewardUnit of MicroAlgos in
    /// that account's AccountData.MicroAlgos.
    ///
    /// Rewards are not compounded (i.e., not added to AccountData.MicroAlgos)
    /// until some other transaction is executed on that account.
    ///
    /// Not compounding rewards allows us to precisely know how many algos
    /// of rewards will be distributed without having to examine every
    /// account to determine if it should get one more algo of rewards
    /// because compounding formed another whole config.Protocol.RewardUnit
    /// of algos.
    pub rewards_state: RewardsState,

    /// Consensus protocol versioning.
    ///
    /// Each block is associated with a version of the consensus protocol,
    /// stored under UpgradeState.current_protocol.  The protocol version
    /// for a block can be determined without having to first decode the
    /// block and its CurrentProtocol field, and this field is present for
    /// convenience and explicitness.  Block.Valid() checks that this field
    /// correctly matches the expected protocol version.
    ///
    /// Each block is associated with at most one active upgrade proposal
    /// (a new version of the protocol).  An upgrade proposal can be made
    /// by a block proposer, as long as no other upgrade proposal is active.
    /// The upgrade proposal lasts for many rounds (UpgradeVoteRounds), and
    /// in each round, that round's block proposer votes to support (or not)
    /// the proposed upgrade.
    ///
    /// If enough votes are collected, the proposal is approved, and will
    /// definitely take effect.  The proposal lingers for some number of
    /// rounds to give clients a chance to notify users about an approved
    /// upgrade, if the client doesn't support it, so the user has a chance
    /// to download updated client software.
    ///
    /// Block proposers influence this upgrade machinery through two fields
    /// in UpgradeVote: UpgradePropose, which proposes an upgrade to a new
    /// protocol, and UpgradeApprove, which signals approval of the current
    /// proposal.
    ///
    /// Once a block proposer determines its UpgradeVote, then UpdateState
    /// is updated deterministically based on the previous UpdateState and
    /// the new block's UpgradeVote.
    pub upgrade_state: UpgradeState,
    pub upgrade_vote: UpgradeVote,

    /// Counts the number of transactions committed in the ledger,
    /// from the time at which support for this feature was introduced.
    ///
    /// Specifically, `tx_counter` is the number of the next transaction that will be committed after this block.
    /// It is 0 when no transactions have ever been committed (since `tx_counter` started being supported).
    pub tx_counter: u64,

    /// Tracks the state of compact certs, potentially for multiple types of certs.
    //msgp:sort protocol.CompactCertType protocol.SortCompactCertType
    pub compact_certs: HashMap<protocol::CompactCertType, CompactCertState>,
}

/// RewardsState represents the global parameters controlling the rate at which accounts accrue rewards.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RewardsState {
    /// The fee sink accepts transaction fees.
    /// It can only spend to the incentive pool.
    pub fee_sink: basics::Address,

    /// The rewards pool accepts periodic injections from the fee sink
    /// and continually redistributes them to adresses as rewards.
    pub rewards_pool: basics::Address,

    /// Specifies how many rewards, in MicroAlgos, have been distributed to each
    /// config.protocol.reward_unit of MicroAlgos since genesis.
    pub rewards_level: u64,

    /// Number of new MicroAlgos added to the participation stake from rewards at the next round.
    pub rewards_rate: u64,

    /// Leftover MicroAlgos after the distribution of rewards_rate/reward_units
    /// MicroAlgos for every reward unit in the next round.
    pub rewards_residue: u64,

    /// The round at which the RewardsRate will be recalculated.
    pub rewards_recalculation_round: basics::Round,
}

/// Represents the vote of the block proposer with respect to protocol upgrades.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct UpgradeVote {
    /// UpgradePropose indicates a proposed upgrade
    pub upgrade_propose: protocol::ConsensusVersion,

    /// UpgradeDelay indicates the time between acceptance and execution
    pub upgrade_delay: basics::Round,

    /// UpgradeApprove indicates a yes vote for the current proposal
    pub upgrade_approve: bool,
}

/// UpgradeState tracks the protocol upgrade state machine.  It is,
/// strictly speaking, computable from the history of all UpgradeVotes
/// but we keep it in the block for explicitness and convenience
/// (instead of materializing it separately, like balances).
//msgp:ignore UpgradeState
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeState {
    pub current_protocol: protocol::ConsensusVersion,
    pub next_protocol: Option<protocol::ConsensusVersion>,
    pub next_protocol_approvals: u64,
    /// NextProtocolVoteBefore specify the last voting round for the next protocol proposal. If there is no voting for
    /// an upgrade taking place, this would be zero.
    pub next_protocol_vote_before: basics::Round,
    /// NextProtocolSwitchOn specify the round number at which the next protocol would be adopted.
    /// If there is no upgrade taking place, nor a wait for the next protocol, this would be zero.
    pub next_protocol_switch_on: basics::Round,
}

/// CompactCertState tracks the state of compact certificates.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompactCertState {
    /// CompactCertVoters is the root of a Merkle tree containing
    /// the online accounts that will help sign a compact certificate.
    /// The Merkle root, and the compact certificate,
    /// happen on blocks that are a multiple of ConsensusParams.CompactCertRounds.
    /// For blocks that are not a multiple of ConsensusParams.CompactCertRounds, this value is zero.
    pub compactcert_voters: CryptoHash,

    /// Total number of MicroAlgos held by the accounts in CompactCertVoters (or zero, if the merkle root is zero).
    /// This is intended for computing the threshold of votes to expect from CompactCertVoters.
    pub compactcert_voters_total: basics::MicroAlgos,

    /// CompactCertNextRound is the next round for which we will accept a CompactCert transaction.
    pub compactcert_next_round: basics::Round,
}

impl Block {
    /// Returns a cryptographic digest summarizing the Block.
    pub fn digest(&self) -> CryptoHash {
        hash_obj(&self.header)
    }

    /// Returns the Round for which the Block is relevant.
    pub fn round(&self) -> basics::Round {
        self.header.round
    }

    /// Returns the consensus protocol params for a block.
    pub fn consensus_protocol(&self) -> &config::ConsensusParams {
        &config::CONSENSUS.0[&self.header.upgrade_state.current_protocol]
    }

    /// Returns the genesis ID from the block header.
    pub fn genesis_id(&self) -> String {
        self.header.genesis_id.clone()
    }

    /// Returns the genesis hash from the block header.
    pub fn genesis_hash(&self) -> CryptoHash {
        self.header.genesis_hash.clone()
    }

    /// WithSeed returns a copy of the Block with the seed set to s.
    pub fn with_seed(&self, s: committee::Seed) -> Block {
        let mut c = self.clone();
        c.header.seed = s;
        return c;
    }

    /// Seed returns the Block's random seed.
    pub fn seed(&self) -> committee::Seed {
        self.header.seed.clone()
    }

    /// Constructs a new valid block with an empty payset and an unset seed.
    pub fn new(prev: &mut BlockHeader) -> Block {
        let (upgrade_vote, upgrade_state) = process_upgrade_params(prev).unwrap();

        let params = &config::CONSENSUS.0[&upgrade_state.current_protocol];

        let mut timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if prev.timestamp > 0 {
            if timestamp < prev.timestamp {
                timestamp = prev.timestamp;
            } else if timestamp > prev.timestamp + params.max_timestamp_increment {
                timestamp = prev.timestamp + params.max_timestamp_increment;
            }
        }

        // the merkle root of TXs will update when fillpayset is called
        let mut blk = Block {
            header: BlockHeader {
                round: basics::Round(prev.round.0 + 1),
                branch: hash_obj(prev),
                upgrade_vote,
                upgrade_state,
                timestamp,
                genesis_id: prev.genesis_id.clone(),
                genesis_hash: prev.genesis_hash.clone(),
                ..Default::default()
            },
            payset: Default::default(),
        };
        blk.header.tx_root = blk.payset_commit().unwrap_or_else(|err| {
            warn!("Block::new(): computing empty tx_root: {:?}", err);
            Default::default()
        });
        // We can't know the entire RewardsState yet, but we can carry over the special addresses.
        blk.header.rewards_state.fee_sink = prev.rewards_state.fee_sink;
        blk.header.rewards_state.rewards_pool = prev.rewards_state.rewards_pool;
        return blk;
    }

    /// Computes the commitment to the payset,
    /// using the appropriate commitment plan based on the block's protocol.
    pub fn payset_commit(&self) -> Result<CryptoHash, ()> {
        let params = &config::CONSENSUS.0[&self.header.upgrade_state.current_protocol];

        match params.payset_commit {
            config::PaysetCommitType::Flat => Ok(self.payset.commit_flat()),
            config::PaysetCommitType::Merkle => Ok(self.tx_merkle_tree()?.root()),
            config::PaysetCommitType::Unsupported => {
                panic!("encountered unsuppported payset commit type")
            }
        }
    }

    /// Checks that the `tx_root` matches what's in the header, as the header is what the block hash authenticates.
    /// If we're given an untrusted block and a known-good hash,
    /// we can't trust the block's transactions unless we validate this.
    fn contents_match_header(&self) -> bool {
        match self.payset_commit() {
            Ok(expected) => expected == self.header.tx_root,
            Err(err) => {
                warn!(
                    "Block::contents_match_header(): cannot compute commitment: {:?}",
                    err
                );
                return false;
            }
        }
    }

    /// Decodes `block.payset` using `decode_signed_tx`, and returns the transactions in groups.
    pub fn DecodePaysetGroups(&self) -> Result<Vec<Vec<transactions::SignedTxWithAD>>, ()> {
        let mut res = Vec::new();
        let mut last_group = Vec::<transactions::SignedTxWithAD>::new();

        for txib in &self.payset.0 {
            let stxad = self.header.decode_signed_tx(txib)?;

            if !last_group.is_empty()
                && (last_group[0].tx.tx.header.group != stxad.tx.tx.header.group
                    || last_group[0].tx.tx.header.group.is_zero())
            {
                res.push(last_group.drain(..).collect());
            }

            last_group.push(stxad);
        }
        if !last_group.is_empty() {
            res.push(last_group);
        }

        return Ok(res);
    }

    /// Decodes `block.payset` using `decode_signed_tx`, and flattens groups.
    pub fn DecodePaysetFlat(&self) -> Result<Vec<transactions::SignedTxWithAD>, ()> {
        let mut res = Vec::new();
        for txib in &self.payset.0 {
            res.push(self.header.decode_signed_tx(txib)?);
        }
        return Ok(res);
    }

    pub fn tx_merkle_tree(&self) -> Result<crypto::merklearray::Tree, ()> {
        crypto::merklearray::Tree::from_block(self)
    }
}

impl BlockHeader {
    /// Checks if this block header is a valid successor to the previous block's header, prev.
    pub fn pre_check(&self, prev: &mut BlockHeader) -> Result<(), ()> {
        // check protocol
        let params = &config::CONSENSUS.0[&self.upgrade_state.current_protocol];

        // check round
        let round = basics::Round(prev.round.0 + 1);
        if round != self.round {
            //return fmt.Errorf("block round incorrect %v != %v", self.round, round)
            return Err(());
        }

        // check the pointer to the previous block
        if self.branch != hash_obj(prev) {
            //return fmt.Errorf("block branch incorrect %v != %v", self.branch, prev.Hash())
            return Err(());
        }

        // check upgrade state
        let next_upgrade_state = prev
            .upgrade_state
            .apply_upgrade_vote(round, &self.upgrade_vote)?;
        if next_upgrade_state != self.upgrade_state {
            //return fmt.Errorf("UpgradeState mismatch: %v != %v", next_upgrade_state, self.upgrade_state)
            return Err(());
        }

        // Check timestamp
        // a zero timestamp allows to put whatever time the proposer wants, but since time is monotonic,
        // there can only be a prefix of zeros (or negative) timestamps in the blockchain.
        if prev.timestamp > 0 {
            // special case when the previous timestamp is zero -- allow a larger window
            if self.timestamp < prev.timestamp {
                //return fmt.Errorf("bad timestamp: current %v < previous %v", self.timestamp, prev.timestamp)
                return Err(());
            } else if self.timestamp > prev.timestamp + params.max_timestamp_increment {
                //return fmt.Errorf("bad timestamp: current %v > previous %v, max increment = %v ", self.timestamp, prev.timestamp, params.max_timestamp_increment)
                return Err(());
            }
        }

        // Check genesis ID value against previous block, if set
        if self.genesis_id == "" {
            //return fmt.Errorf("genesis ID missing")
            return Err(());
        }
        if prev.genesis_id != "" && prev.genesis_id != self.genesis_id {
            //return fmt.Errorf("genesis ID mismatch: %s != %s", self.genesis_id, prev.genesis_id)
            return Err(());
        }

        // Check genesis hash value against previous block, if set
        if params.support_genesis_hash {
            if self.genesis_hash == Default::default() {
                //return fmt.Errorf("genesis hash missing")
                return Err(());
            }
            if prev.genesis_hash != Default::default() && prev.genesis_hash != self.genesis_hash {
                //return fmt.Errorf("genesis hash mismatch: %s != %s", self.genesis_hash, prev.genesis_hash)
                return Err(());
            }
        } else {
            if self.genesis_hash != Default::default() {
                //return fmt.Errorf("genesis hash not allowed: %s", self.genesis_hash)
                return Err(());
            }
        }

        return Ok(());
    }

    /// Returns information about the next expected protocol version
    /// (the ConsensusVersion object, the round in whichh it is supposed to switch on, and whether it is supported).
    /// If no upgrade is scheduled, return the current protocol.
    pub fn next_version_info(&self) -> (Option<protocol::ConsensusVersion>, basics::Round, bool) {
        // TODO handle supported check with enum (maybe introduce `Unsupported` enum variant
        //_, supported = config.Consensus[ver]
        if self.round >= self.upgrade_state.next_protocol_vote_before
            && self.round < self.upgrade_state.next_protocol_switch_on
        {
            (
                self.upgrade_state.next_protocol,
                self.upgrade_state.next_protocol_switch_on,
                true,
            )
        } else {
            (
                Some(self.upgrade_state.current_protocol),
                basics::Round(self.round.0 + 1),
                true,
            )
        }
    }

    /// Converts a `SignedTxInBlock` from a block to a `SignedTxWithAD`.
    pub fn decode_signed_tx(
        &self,
        stb: &transactions::SignedTxInBlock,
    ) -> Result<transactions::SignedTxWithAD, ()> {
        let mut stad = stb.tx.clone();

        let proto = &config::CONSENSUS.0[&self.upgrade_state.current_protocol];
        if !proto.support_signed_tx_in_block {
            return Ok(stad);
        }

        if stb.tx.tx.tx.header.genesis_id != "" {
            //return Err(fmt.Errorf("GenesisID <%s> not empty", st.Txn.GenesisID));
            return Err(());
        }

        if stb.has_genesis_id {
            stad.tx.tx.header.genesis_id = self.genesis_id.clone();
        }

        if stb.tx.tx.tx.header.genesis_hash != Default::default() {
            //return fmt.Errorf("GenesisHash <%v> not empty", st.Txn.GenesisHash)
            return Err(());
        }

        if proto.require_genesis_hash {
            if stb.has_genesis_hash {
                //return fmt.Errorf("HasGenesisHash set to true but RequireGenesisHash obviates the flag")
                return Err(());
            }
            stad.tx.tx.header.genesis_hash = self.genesis_hash.clone();
        } else {
            if stb.has_genesis_hash {
                stad.tx.tx.header.genesis_hash = self.genesis_hash.clone();
            }
        }

        return Ok(stad);
    }

    /// Converts a `SignedTxWithAD` into a `SignedTxInBlock` for this block.
    pub fn encode_signed_tx(
        &self,
        mut st: transactions::SignedTx,
        ad: transactions::ApplyData,
    ) -> Result<transactions::SignedTxInBlock, ()> {
        let mut has_genesis_id = false;
        let mut has_genesis_hash = false;

        let proto = &config::CONSENSUS.0[&self.upgrade_state.current_protocol];
        if !proto.support_signed_tx_in_block {
            let stad = transactions::SignedTxWithAD { tx: st, ad };
            return Ok(transactions::SignedTxInBlock {
                tx: stad,
                has_genesis_id,
                has_genesis_hash,
            });
        }

        if st.tx.header.genesis_id != "" {
            if st.tx.header.genesis_id == self.genesis_id {
                st.tx.header.genesis_id = "".to_owned();
                has_genesis_id = true;
            } else {
                //return fmt.Errorf("GenesisID mismatch: %s != %s", st.Txn.GenesisID, bh.GenesisID)
                return Err(());
            }
        }

        if st.tx.header.genesis_hash != Default::default() {
            if st.tx.header.genesis_hash == self.genesis_hash {
                st.tx.header.genesis_hash = Default::default();
                if !proto.require_genesis_hash {
                    has_genesis_hash = true;
                }
            } else {
                //return fmt.Errorf("GenesisHash mismatch: %v != %v", st.Txn.GenesisHash, bh.GenesisHash)
                return Err(());
            }
        } else {
            if proto.require_genesis_hash {
                //return fmt.Errorf("GenesisHash required but missing")
                return Err(());
            }
        }

        let stad = transactions::SignedTxWithAD { tx: st, ad };
        return Ok(transactions::SignedTxInBlock {
            tx: stad,
            has_genesis_id,
            has_genesis_hash,
        });
    }
}

impl RewardsState {
    /// Computes the RewardsState of the subsequent round given the subsequent consensus parameters,
    /// along with the incentive pool balance and the total reward units in the system as of the current round.
    pub fn next_state(
        &self,
        next_round: basics::Round,
        next_proto: config::ConsensusParams,
        incentive_pool_balance: basics::MicroAlgos,
        total_reward_units: u64,
    ) -> Self {
        let mut next_state = self.clone();

        if next_round == self.rewards_recalculation_round {
            let mut max_spent_over = next_proto.min_balance;

            if next_proto.pending_residue_rewards {
                match max_spent_over.checked_add(self.rewards_residue) {
                    Some(n) => max_spent_over = n,
                    None => {
                        error!("overflowed when trying to accumulate min_balance({}) and rewards_residue({}) for round {} (state {:?})", next_proto.min_balance, self.rewards_residue, next_round, self);
                        // this should never happen, but if it does, adjust the maxSpentOver so that we will have no rewards.
                        max_spent_over = incentive_pool_balance.0;
                    }
                }
            }

            // it is time to refresh the rewards rate
            let new_rate = match incentive_pool_balance.0.checked_add(max_spent_over) {
                Some(n) => n,
                None => {
                    error!(
                        "overflowed when trying to refresh rewards_rate for round {} (state {:?})",
                        next_round, self
                    );
                    0
                }
            };

            next_state.rewards_rate = new_rate / next_proto.rewards_rate_refresh_interval;
            next_state.rewards_recalculation_round =
                next_round + basics::Round(next_proto.rewards_rate_refresh_interval);
        }

        if total_reward_units == 0 {
            // there are no reward units, so keep the previous rewards level
            return next_state;
        }

        let rewards_with_residue = self.rewards_rate.checked_add(self.rewards_residue);

        if rewards_with_residue.is_none() {
            error!("could not compute next reward level (current level {}, adding {} in total, number of reward units {}) using old level",
                self.rewards_level, self.rewards_rate, total_reward_units);
            return next_state;
        }

        let next_reward_level = self
            .rewards_level
            .checked_add(rewards_with_residue.unwrap() / total_reward_units);

        if next_reward_level.is_none() {
            error!("could not compute next reward level (current level {}, adding {} in total, number of reward units {}) using old level",
                self.rewards_level, self.rewards_rate, total_reward_units);
            return next_state;
        }

        let next_residue = rewards_with_residue.unwrap() % total_reward_units;
        next_state.rewards_level = next_reward_level.unwrap();
        next_state.rewards_residue = next_residue;
        return next_state;
    }
}

impl UpgradeState {
    /// Determines the UpgradeState for a block at round r,
    /// given the previous block's UpgradeState "s" and this block's UpgradeVote.
    ///
    /// This function returns an error if the input is not valid in prev_state:
    /// that is, if UpgradePropose shows up when there is already an active proposal,
    /// or if UpgradeApprove shows up if there is no active proposal being voted on.
    fn apply_upgrade_vote(
        &mut self,
        round: basics::Round,
        vote: &UpgradeVote,
    ) -> Result<UpgradeState, ()> {
        // Locate the config parameters for current protocol
        let params = &config::CONSENSUS.0[&self.current_protocol];

        // Apply proposal of upgrade to new protocol
        if vote.upgrade_propose != self.current_protocol {
            if self.next_protocol != Some(self.current_protocol) {
                //err = fmt.Errorf("applyUpgradeVote: new proposal during existing proposal")
                return Err(());
            }

            /*
            if vote.upgrade_propose.len() > params.max_version_string_len {
                //err = fmt.Errorf("applyUpgradeVote: proposed protocol version %s too long", vote.UpgradePropose)
                return Err(());
            }
            */

            let mut upgrade_delay = vote.upgrade_delay.0;
            if upgrade_delay > params.max_upgrade_wait_rounds
                || upgrade_delay < params.min_upgrade_wait_rounds
            {
                //err = fmt.Errorf("applyUpgradeVote: proposed upgrade wait rounds %d out of permissible range [%d, %d]", upgradeDelay, params.MinUpgradeWaitRounds, params.MaxUpgradeWaitRounds)
                return Err(());
            }

            if upgrade_delay == 0 {
                upgrade_delay = params.default_upgrade_wait_rounds;
            }

            self.next_protocol = Some(vote.upgrade_propose);
            self.next_protocol_approvals = 0;
            self.next_protocol_vote_before = basics::Round(round.0 + params.upgrade_vote_rounds);
            self.next_protocol_switch_on =
                basics::Round(round.0 + params.upgrade_vote_rounds + upgrade_delay);
        } else {
            if vote.upgrade_delay != basics::Round(0) {
                //err = fmt.Errorf("applyUpgradeVote: upgrade delay %d nonzero when not proposing", vote.UpgradeDelay)
                return Err(());
            }
        }

        // Apply approval of existing protocol upgrade
        if vote.upgrade_approve {
            if self.next_protocol == Some(self.current_protocol) {
                //err = fmt.Errorf("applyUpgradeVote: approval without an active proposal")
                return Err(());
            }

            if round >= self.next_protocol_vote_before {
                //err = fmt.Errorf("applyUpgradeVote: approval after vote deadline")
                return Err(());
            }

            self.next_protocol_approvals += 1;
        }

        // Clear out failed proposal
        if round == self.next_protocol_vote_before
            && self.next_protocol_approvals < params.upgrade_threshold
        {
            self.next_protocol = self.next_protocol;
            self.next_protocol_approvals = 0;
            self.next_protocol_vote_before = basics::Round(0);
            self.next_protocol_switch_on = basics::Round(0);
        }

        // Switch over to new approved protocol
        if round == self.next_protocol_switch_on {
            self.current_protocol = self.next_protocol.unwrap();
            self.next_protocol = self.next_protocol;
            self.next_protocol_approvals = 0;
            self.next_protocol_vote_before = basics::Round(0);
            self.next_protocol_switch_on = basics::Round(0);
        }

        Ok(self.clone())
    }
}

/// Determines our upgrade vote, applies it, and returns the generated `UpgradeVote` and the new `UpgradeState`.
// TODO should `prev` be mut, ref, or mut ref
pub fn process_upgrade_params(prev: &mut BlockHeader) -> Result<(UpgradeVote, UpgradeState), ()> {
    // Find parameters for current protocol; panic if not supported
    let prev_params = &config::CONSENSUS.0[&prev.upgrade_state.current_protocol];

    // Decide on the votes for protocol upgrades
    let mut upgrade_vote = UpgradeVote::default();

    // If there is no upgrade proposal, see if we can make one
    if prev.upgrade_state.next_protocol.is_none() {
        if let Some((&k, &v)) = prev_params.approved_upgrades.iter().next() {
            upgrade_vote.upgrade_propose = k;
            upgrade_vote.upgrade_delay = basics::Round(v);
            upgrade_vote.upgrade_approve = true;
        }
    }

    // If there is a proposal being voted on, see if we approve it
    let round = prev.round + basics::Round(1);
    if round < prev.upgrade_state.next_protocol_vote_before {
        upgrade_vote.upgrade_approve = prev_params
            .approved_upgrades
            .contains_key(&prev.upgrade_state.next_protocol.unwrap());
    }

    let upgrade_state = prev
        .upgrade_state
        .apply_upgrade_vote(round, &upgrade_vote)?;
    /*if err != nil {
        err = fmt.Errorf("constructed invalid upgrade vote %v for round %v in state %v: %v", upgradeVote, round, prev.UpgradeState, err)
        return
    }*/

    return Ok((upgrade_vote, upgrade_state));
}

/// Splits a slice of `SignedTx`s into groups.
pub fn signed_txs_to_group(txs: &[transactions::SignedTx]) -> Vec<Vec<transactions::SignedTx>> {
    let mut res = Vec::new();
    let mut last_group: Vec<transactions::SignedTx> = Vec::new();
    for tx in txs {
        if !last_group.is_empty()
            && (last_group[0].tx.header.group != tx.tx.header.group
                || last_group[0].tx.header.group.is_zero())
        {
            res.push(last_group.drain(..).collect())
        }

        last_group.push(tx.clone());
    }
    if !last_group.is_empty() {
        res.push(last_group);
    }
    return res;
}

/// Combines all groups into a flat slice of `SignedTx`s.
pub fn signed_tx_groups_flatten(
    tx_groups: Vec<Vec<transactions::SignedTx>>,
) -> Vec<transactions::SignedTx> {
    let mut res = Vec::new();
    for tx_group in &tx_groups {
        res.extend_from_slice(&tx_group);
    }
    return res;
}

impl Hashable for BlockHeader {
    /// ToBeHashed implements the crypto.Hashable interface
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        return (protocol::BLOCK_HEADER, protocol::encode(&self));
    }
}
