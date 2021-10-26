// Copyright (C) 2021 qkniep <qkniep@qk-huawei>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::block::{Block, BlockHeader, RewardsState, UpgradeState, UpgradeVote};
use crate::{
    config,
    crypto::{self, hashable::Hashable},
    data::{basics, committee, transactions},
    protocol,
};

/// MaxInitialGenesisAllocationSize is the maximum number of accounts that are supported when
/// bootstrapping a new network. The number of account *can* grow further after the bootstrapping.
/// This value is used exclusively for the messagepack decoder, and has no affect on the network
/// capabilities/capacity in any way.
const MAX_INITIAL_GENESIS_ALLOCATION_SIZE: usize = 100_000_000;

/// Defines an Algorand "universe" -- a set of nodes that can talk to each other,
/// agree on the ledger contents, etc.
/// This is defined by the initial account states (GenesisAllocation),
/// the initial consensus protocol (GenesisProto), and the schema of the ledger.
#[derive(Serialize, Deserialize)]
struct Genesis {
    //_struct struct{} `codec:",omitempty,omitemptyarray"`
    /// The SchemaID allows nodes to store data specific to a particular
    /// universe (in case of upgrades at development or testing time),
    /// and as an optimization to quickly check if two nodes are in
    /// the same universe.
    pub schema_id: String,

    /// Network identifies the unique algorand network for which the ledger is valid.
    /// Note the Network name should not include a '-', as we generate the GenesisID from "<Network>-<SchemaID>";
    /// the '-' makes it easy to distinguish between the network and schema.
    // TODO: change NetworkID to String?
    pub network: protocol::NetworkID,

    /// Consensus protocol in use at the genesis block.
    pub proto: protocol::ConsensusVersion,

    /// The initial accounts and their state.
    pub allocation: Vec<GenesisAllocation>,

    /// Address of the rewards pool.
    pub rewards_pool: String,

    /// Address of the fee sink.
    pub fee_sink: String,

    /// Timestamp for the genesis block.
    pub timestamp: u64,

    /// Arbitrary genesis comment string - will be excluded from file if empty.
    pub comment: String,

    /// Defines whether this network operates in a developer mode or not.
    /// Developer mode networks are a single node network, that operates without the agreement service being active.
    /// In liue of the agreement service, a new block is generated each time a node receives a transaction group.
    /// The default value for this field is "false", which makes this field empty from it's encoding,
    /// and therefore backward compatible.
    pub dev_mode: bool,
}

impl Genesis {
    // MakeGenesisBlock creates a genesis block, including setup of RewardsState.
    fn new(
        proto: protocol::ConsensusVersion,
        gen_bal: GenesisBalances,
        id: &str,
        hash: crypto::CryptoHash,
    ) -> Result<Block, ()> {
        let params = &config::CONSENSUS.0[&proto];

        let mut genesis_rewards_state = RewardsState {
            fee_sink: gen_bal.fee_sink,
            rewards_pool: gen_bal.rewards_pool,
            rewards_level: 0,
            rewards_rate: 0,
            rewards_residue: 0,
            rewards_recalculation_round: basics::Round(params.rewards_rate_refresh_interval),
        };

        let initial_rewards = gen_bal.balances[&gen_bal.rewards_pool].micro_algos.0;
        if params.initial_rewards_rate_calculation {
            genesis_rewards_state.rewards_rate = initial_rewards.saturating_sub(params.min_balance)
                / params.rewards_rate_refresh_interval;
        } else {
            genesis_rewards_state.rewards_rate =
                initial_rewards / params.rewards_rate_refresh_interval;
        }

        let mut blk = Block {
            header: BlockHeader {
                round: basics::Round(0),
                branch: crypto::CryptoHash::default(),
                seed: committee::Seed(hash.0),
                tx_root: transactions::Payset::default().commit_genesis(),
                timestamp: gen_bal.timestamp,
                genesis_id: id.to_owned(),
                rewards_state: genesis_rewards_state,
                upgrade_state: UpgradeState {
                    current_protocol: proto,
                    ..Default::default()
                },
                upgrade_vote: UpgradeVote::default(),
                ..Default::default()
            },
            payset: transactions::Payset::default(),
        };

        if params.support_genesis_hash {
            blk.header.genesis_hash = hash;
        }

        Ok(blk)
    }

    /// Attempts to load a `Genesis` structure from a (presumably) genesis.json file.
    // TODO update once actual JSON encoding is implemented
    fn load_from_file<P: AsRef<std::path::Path>>(genesis_file: P) -> Result<Genesis, ()> {
        // Load genesis.json
        let file = std::fs::File::open(&genesis_file).unwrap();
        let genesis: Genesis = rmp_serde::decode::from_read(file).unwrap();
        Ok(genesis)
    }

    /// ID is the effective Genesis identifier - the combination
    /// of the network and the ledger schema version
    fn id(&self) -> String {
        format!("{}-{}", self.network, self.schema_id)
    }
}

/// A GenesisAllocation object represents an allocation of algos to an address in the genesis block.
#[derive(Serialize, Deserialize)]
struct GenesisAllocation {
    // Unfortunately we forgot to specify omitempty, and now
    // this struct must be encoded without omitempty for the
    // Address, Comment, and State fields..
    //_struct struct{} `codec:""`
    /// Address is the checksummed short address.
    pub address: String,
    /// Comment is a note about what this address is representing, and is purely informational.
    pub comment: String,
    /// State is the initial account state.
    pub state: basics::AccountData,
}

impl Hashable for Genesis {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::GENESIS, protocol::encode(self))
    }
}

/// Contains the information needed to generate a new ledger.
struct GenesisBalances {
    pub balances: HashMap<basics::Address, basics::AccountData>,
    pub fee_sink: basics::Address,
    pub rewards_pool: basics::Address,
    pub timestamp: u64,
}

impl GenesisBalances {
    /// Returns the information needed to bootstrap the ledger based on the current time.
    fn new(
        balances: HashMap<basics::Address, basics::AccountData>,
        fee_sink: basics::Address,
        rewards_pool: basics::Address,
    ) -> Self {
        let mut timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::with_timestamp(balances, fee_sink, rewards_pool, timestamp)
    }

    /// Returns the information needed to bootstrap the ledger based on a given time.
    fn with_timestamp(
        balances: HashMap<basics::Address, basics::AccountData>,
        fee_sink: basics::Address,
        rewards_pool: basics::Address,
        timestamp: u64,
    ) -> Self {
        Self {
            balances,
            fee_sink,
            rewards_pool,
            timestamp,
        }
    }
}
