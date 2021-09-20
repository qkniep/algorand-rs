// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::time::Duration;

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

use super::protocol;
use super::Result;

/// Specifies settings that might vary based on the
/// particular version of the consensus protocol.
#[derive(Clone, Serialize, Deserialize)]
struct ConsensusParams {
    // Consensus protocol upgrades. Votes for upgrades are collected for
    // upgrade_vote_rounds. If the number of positive votes is over
    // upgrade_threshold, the proposal is accepted.
    //
    // upgrade_vote_rounds needs to be long enough to collect an
    // accurate sample of participants, and upgrade_threshold needs
    // to be high enough to ensure that there are sufficient participants
    // after the upgrade.
    //
    // A consensus protocol upgrade may specify the delay between its
    // acceptance and its execution.  This gives clients time to notify
    // users.  This delay is specified by the upgrade proposer and must
    // be between min_upgrade_wait_rounds and max_upgrade_wait_rounds (inclusive)
    // in the old protocol's parameters.  Note that these parameters refer
    // to the representation of the delay in a block rather than the actual
    // delay: if the specified delay is zero, it is equivalent to
    // default_upgrade_wait_rounds.
    //
    // The maximum length of a consensus version string is
    // max_version_string_len.
    pub upgrade_vote_rounds: u64,
    pub upgrade_threshold: u64,
    pub default_upgrade_wait_rounds: u64,
    pub min_upgrade_wait_rounds: u64,
    pub max_upgrade_wait_rounds: u64,
    pub max_version_string_len: i32,

    /// Determines the maximum number of bytes that transactions can take up in a block.
    /// Specifically, the sum of the lengths of encodings of each transaction
    /// in a block must not exceed max_txn_bytes_per_block.
    pub max_txn_bytes_per_block: i32,

    /// The maximum size of a transaction's Note field.
    pub max_txn_note_bytes: i32,

    /// How long a transaction can be live for:
    /// the maximum difference between last_valid and first_valid.
    ///
    /// Note that in a protocol upgrade, the ledger must first be upgraded
    /// to hold more past blocks for this value to be raised.
    pub max_txn_life: u64,

    /// approved_upgrades describes the upgrade proposals that this protocol
    /// implementation will vote for, along with their delay value
    /// (in rounds).  A delay value of zero is the same as a delay of
    /// default_upgrade_wait_rounds.
    pub approved_upgrades: HashMap<protocol::ConsensusVersion, u64>,

    /// Indicates support for the genesis_hash fields in transactions (and requires them in blocks).
    pub support_genesis_hash: bool,

    /// Indicates that genesis_hash must be present in every transaction.
    pub require_genesis_hash: bool,

    /// Specifies the granularity of top-level ephemeral keys.
    /// key_dilution is the number of second-level keys in each batch,
    /// signed by a top-level "batch" key.  The default value can be
    /// overridden in the account state.
    pub default_key_dilution: u64,

    /// Specifies the minimum balance that can appear in an account.
    /// To spend money below min_balance requires issuing
    /// an account-closing transaction, which transfers all of the
    /// money from the account, and deletes the account state.
    pub min_balance: u64,

    /// Specifies the minimum fee allowed on a transaction.
    /// A minimum fee is necessary to prevent do_s. In some sense this is
    /// a way of making the spender subsidize the cost of storing this transaction.
    pub min_txn_fee: u64,

    /// Specifies that the sum of the fees in a
    /// group must exceed one min_txn_fee per Txn, rather than check that
    /// each Txn has a min_fee.
    pub enable_fee_pooling: bool,

    /// Specifies that the sum of fees for application calls
    /// in a group is checked against the sum of the budget for application calls,
    /// rather than check each individual app call is within the budget.
    pub enable_app_cost_pooling: bool,

    /// Specifies the number of micro_algos corresponding to one reward unit.
    ///
    /// Rewards are received by whole reward units.  Fractions of
    /// reward_units do not receive rewards.
    pub reward_unit: u64,

    /// Number of rounds after which the rewards level is recomputed
    /// for the next rewards_rate_refresh_interval rounds.
    pub rewards_rate_refresh_interval: u64,

    // seed-related parameters
    /// how many blocks back we use seeds from in sortition (delta_s in the spec)
    pub seed_lookback: u64,
    /// how often an old block hash is mixed into the seed. delta_r in the spec
    pub seed_refresh_interval: u64,

    /// Ledger retention policy.
    /// `(current round - max_bal_lookback)` is the oldest round the ledger must answer balance queries for.
    pub max_bal_lookback: u64,

    // sortition threshold factors
    pub num_proposers: u64,
    pub soft_committee_size: u64,
    pub soft_committee_threshold: u64,
    pub cert_committee_size: u64,
    pub cert_committee_threshold: u64,
    pub next_committee_size: u64, // for any non-FPR votes >= deadline step, committee sizes and thresholds are constant
    pub next_committee_threshold: u64,
    pub late_committee_size: u64,
    pub late_committee_threshold: u64,
    pub redo_committee_size: u64,
    pub redo_committee_threshold: u64,
    pub down_committee_size: u64,
    pub down_committee_threshold: u64,

    /// time for nodes to wait for block proposal headers for period > 0, value should be set to 2 * small_lambda
    pub agreement_filter_timeout: std::time::Duration,
    /// time for nodes to wait for block proposal headers for period = 0, value should be configured to suit best case
    /// critical path
    pub agreement_filter_timeout_period0: std::time::Duration,

    pub fast_recovery_lambda: std::time::Duration, // time between fast recovery attempts
    pub fast_partition_recovery: bool,             // set when fast partition recovery is enabled

    /// How to commit to the payset: flat or merkle tree.
    pub payset_commit: PaysetCommitType,

    /// Maximum time between timestamps on successive blocks.
    pub max_timestamp_increment: i64,

    /// Support for the efficient encoding in signed_txn_in_block.
    pub support_signed_txn_in_block: bool,

    /// Force the `fee_sink` address to be non-participating in the genesis balances.
    pub force_non_participating_fee_sink: bool,

    /// Support for `apply_data` in `signed_txn_in_block`.
    pub apply_data: bool,

    /// Track reward distributions in `apply_data`.
    pub rewards_in_apply_data: bool,

    /// Domain-separated credentials.
    pub credential_domain_separation_enabled: bool,

    /// Support for transactions that mark an account non-participating.
    pub support_become_non_participating_transactions: bool,

    /// Fix the rewards calculation by avoiding subtracting too much from the rewards pool.
    pub pending_residue_rewards: bool,

    /// Asset support.
    pub Asset: bool,

    /// Max number of assets per account.
    pub max_assets_per_account: i32,

    /// Max length of asset name.
    pub max_asset_name_bytes: i32,

    /// Max length of asset unit name.
    pub max_asset_unit_name_bytes: i32,

    /// Max length of asset URL.
    pub max_asset_uRLBytes: i32,

    /// Support sequential transaction counter `txn_counter`.
    pub txn_counter: bool,

    /// Transaction groups.
    pub support_tx_groups: bool,

    /// Max group size.
    pub max_tx_group_size: i32,

    /// Support for transaction leases.
    /// Note: If `fix_transaction_leases` is not set, the transaction leases supported are faulty;
    /// specifically, they do not enforce exclusion correctly when the `first_valid` of transactions do not match.
    pub support_transaction_leases: bool,
    pub fix_transaction_leases: bool,

    /// 0 for no support, otherwise highest version supported
    pub logic_sig_version: u64,

    /// len(logic_sig.Logic) + len(logic_sig.Args[*]) must be less than this
    pub logic_sig_max_size: u64,

    /// Sum of estimated op cost must be less than this.
    pub logic_sig_max_cost: u64,

    /// Max decimal precision for assets.
    pub max_asset_decimals: u32,

    /// Support_rekeying indicates support for account rekeying (the rekey_to and auth_addr fields).
    pub support_rekeying: bool,

    /// Application support.
    pub Application: bool,

    /// Max number of application_args for an application_call transaction.
    pub max_app_args: i32,

    /// Max for `sum([len(arg) for arg in txn.application_args])`.
    pub max_app_total_arg_len: i32,

    /// Maximum byte length of application approval program or clear state.
    /// When max_extra_app_program_pages > 0, this is the size of those pages.
    /// So two "extra pages" would mean 3*max_app_program_len bytes are available.
    pub max_app_program_len: i32,

    /// Maximum total length of an application's programs (approval + clear state).
    /// When max_extra_app_program_pages > 0, this is the size of those pages.
    /// So two "extra pages" would mean 3*max_app_total_program_len bytes are available.
    pub max_app_total_program_len: i32,

    /// Extra length for application program in pages. A page is `max_app_program_len` bytes.
    pub max_extra_app_program_pages: i32,

    /// Maximum number of accounts in the application_call Accounts field.
    /// This determines, in part, the maximum number of balance records accessed by a single transaction.
    pub max_app_txn_accounts: i32,

    /// Maximum number of app ids in the application_call foreign_apps field.
    /// These are the only applications besides the called application
    /// for which global state may be read in the transaction.
    pub max_app_txn_foreign_apps: i32,

    /// Maximum number of asset ids in the application_call foreign_assets field.
    /// These are the only assets for which the asset parameters may be read in the transaction.
    pub max_app_txn_foreign_assets: i32,

    /// Maximum number of "foreign references" (accounts, asa, app) that can be attached to a single app call.
    pub max_app_total_txn_references: i32,

    /// Maximum cost of application approval program or clear state program.
    pub max_app_program_cost: i32,

    /// Maximum length of a key used in an application's global or local key/value store.
    pub max_app_key_len: i32,

    /// Maximum length of a bytes value used in an application's global or local key/value store.
    pub max_app_bytes_value_len: i32,

    /// Maximum sum of the lengths of the key and value of one app state entry.
    pub max_app_sum_key_value_lens: i32,

    /// Maximum number of inner transactions that can be created by an app call.
    pub max_inner_transactions: i32,

    /// Maximum number of applications a single account can create and store `app_params` for at once.
    pub max_apps_created: i32,

    /// Maximum number of applications a single account can opt in to and store `app_local_state` for at once.
    pub max_apps_opted_in: i32,

    /// Flat `min_balance` requirement for creating a single application and storing its `app_params`.
    pub app_flat_params_min_balance: u64,

    /// Flat min_balance requirement for opting in to a single application and storing its `app_local_state`.
    pub app_flat_opt_in_min_balance: u64,

    /// `min_balance` requirement per key/value entry in local_state or
    /// global_state key/value stores, regardless of value type
    pub schema_min_balance_per_entry: u64,

    /// `min_balance` requirement (in addition to schema_min_balance_per_entry) for
    /// integer values stored in local_state or global_state key/value stores
    pub schema_uint_min_balance: u64,

    /// `min_balance` requirement (in addition to schema_min_balance_per_entry) for
    /// byte array values stored in local_state or global_state key/value stores
    pub schema_bytes_min_balance: u64,

    /// Maximum number of total key/value pairs allowed by a given
    /// `local_state_schema` (and therefore allowed in `local_state`).
    pub max_local_schema_entries: u64,

    /// Maximum number of total key/value pairs allowed by a given
    /// global_state_schema (and therefore allowed in global_state).
    pub max_global_schema_entries: u64,

    /// Maximum total minimum balance requirement for an account,
    /// used to limit the maximum size of a single balance record.
    pub maximum_minimum_balance: u64,

    /// Defines the frequency with which compact certificates are generated.
    /// Every round that is a multiple of compact_cert_rounds,
    /// the block header will include a Merkle commitment to the set of online accounts
    /// (that can vote after another compact_cert_rounds rounds),
    /// and that block will be signed (forming a compact certificate)
    /// by the voters from the previous such Merkle tree commitment.
    /// A value of zero means no compact certificates.
    pub compact_cert_rounds: u64,

    /// Bound on how many online accounts get to participate in forming the compact certificate,
    /// by including the top `compact_cert_top_voters` accounts (by normalized balance) into the Merkle commitment.
    pub compact_cert_top_voters: u64,

    /// Number of blocks we skip before publishing a Merkle commitment to the online accounts.
    /// Namely, if block number N contains a Merkle commitment to the online
    /// accounts (which, incidentally, means N%compact_cert_rounds=0),
    /// then the balances reflected in that commitment must come from
    /// block N-compact_cert_voters_lookback.
    /// This gives each node some time (compact_cert_voters_lookback blocks worth of time)
    /// to construct this Merkle tree, so as to avoid placing the
    /// construction of this Merkle tree (and obtaining the requisite
    /// accounts and balances) in the critical path.
    pub compact_cert_voters_lookback: u64,

    /// Specifies the fraction of top voters weight that must sign the message (block header) for security.
    /// The compact certificate ensures this threshold holds; however,
    /// forming a valid compact certificate requires a somewhat higher number of signatures,
    /// and the more signatures are collected, the smaller the compact cert can be.
    ///
    /// This threshold can be thought of as the maximum fraction of
    /// malicious weight that compact certificates defend against.
    ///
    /// The threshold is computed as compact_cert_weight_threshold/(1<<32).
    pub compact_cert_weight_threshold: u32,

    /// Security parameter (k+q) for the compact certificate scheme.
    pub compact_cert_sec_kQ: u32,

    /// Adds an extra field to the apply_data. The field contains the amount of the remaining
    /// asset that were sent to the close-to address.
    pub enable_asset_close_amount: bool,

    /// Update the initial rewards rate calculation to take the reward pool minimum balance into account.
    pub initial_rewards_rate_calculation: bool,

    /// Updates how apply_delta.eval_delta.local_deltas are stored.
    pub no_empty_local_deltas: bool,

    /// Enables the following extra checks on key registration transactions:
    ///   1) checking that [vote_pK/selection_pK/vote_key_dilution] are all set or all clear.
    ///   2) checking that the vote_first is less or equal to vote_last.
    ///   3) checking that in the case of going offline, both the vote_first and vote_last are clear.
    ///   4) checking that in the case of going online the vote_last is non-zero and greater then the current network round.
    ///   5) checking that in the case of going online the vote_first is less or equal to the last_valid+1.
    ///   6) checking that in the case of going online the vote_first is less or equal to the next network round.
    pub enable_keyreg_coherency_check: bool,

    pub enable_extra_pages_on_app_update: bool,
}

/// Enumerates possible ways for the block header to commit to the set of transactions in the block.
#[derive(Clone, Copy)]
enum PaysetCommitType {
    /// Early protocols used a Merkle tree to commit to the transactions.
    /// This is no longer supported.
    Unsupported,

    /// Hashes the entire payset array.
    Flat,

    /// Uses merklearray to commit to the payset.
    Merkle,
}

/// Defines a set of supported protocol versions and their
/// corresponding parameters.
#[derive(Clone, Serialize, Deserialize)]
struct ConsensusProtocols(HashMap<protocol::ConsensusVersion, ConsensusParams>);

lazy_static! {
    static ref CONSENSUS: ConsensusProtocols = {
        let mut cp = ConsensusProtocols::new();
        init_consensus_protocols(&mut cp);
        load_configurable_consensus_protocols(".", &mut cp);
        for (_, &mut p) in cp.0.iter_mut() {
            check_set_alloc_bounds(p);
        }
        cp
    };
}
/* TODO get rid of this fucking global state
/// Tracks the protocol-level settings for different versions of the consensus protocol.
var Consensus ConsensusProtocols

/// Largest threshold for a bundle over all supported consensus protocols.
/// Used for decoding purposes.
var MaxVoteThreshold int

/// Largest number of accounts that may appear in an eval delta.
/// Used for decoding purposes.
var MaxEvalDeltaAccounts int

/// Largest number of key/value pairs that may appear in a StateDelta.
/// Used for decoding purposes.
var MaxStateDeltaKeys int

// MaxLogCalls is the highest allowable log messages that may appear in
// any version, used only for decoding purposes. Never decrease this value.
var MaxLogCalls int

// MaxInnerTransactions is the maximum number of inner transactions that may be created in an app call.
var MaxInnerTransactions int

// MaxLogicSigMaxSize is the largest logical signature appear in any of the supported
// protocols, used for decoding purposes.
var MaxLogicSigMaxSize int

// MaxTxnNoteBytes is the largest supported nodes field array size supported by any
// of the consensus protocols. used for decoding purposes.
var MaxTxnNoteBytes int

// MaxTxGroupSize is the largest supported number of transactions per transaction group supported by any
// of the consensus protocols. used for decoding purposes.
var MaxTxGroupSize int

// MaxAppProgramLen is the largest supported app program size supported by any
// of the consensus protocols. used for decoding purposes.
var MaxAppProgramLen int

// MaxBytesKeyValueLen is a maximum length of key or value across all protocols.
// used for decoding purposes.
var MaxBytesKeyValueLen int

// MaxExtraAppProgramLen is the maximum extra app program length supported by any
// of the consensus protocols. used for decoding purposes.
var MaxExtraAppProgramLen int

// MaxAvailableAppProgramLen is the largest supported app program size include the extra pages
//supported supported by any of the consensus protocols. used for decoding purposes.
var MaxAvailableAppProgramLen int
*/

fn check_set_max(value: i32, cur_max: &mut i32) {
    if value > *cur_max {
        *cur_max = value;
    }
}

/// Sets some global variables used during msgpack decoding to enforce memory allocation limits.
/// The values should be generous to prevent correctness bugs, but not so large that DoS attacks are trivial.
fn check_set_alloc_bounds(p: ConsensusParams) {
    let max_vote_threshold = [
        p.soft_committee_threshold,
        p.cert_committee_threshold,
        p.next_committee_threshold,
        p.late_committee_threshold,
        p.redo_committee_threshold,
        p.down_committee_threshold,
    ]
    .iter()
    .max()
    .unwrap();

    // These bounds could be tighter, but since these values are just to prevent DoS,
    // setting them to be the maximum number of allowed executed TEAL instructions should be fine (order of ~1000).
    check_set_max(p.max_app_program_len, &mut max_state_delta_keys);
    check_set_max(p.max_app_program_len, &mut max_eval_delta_accounts);
    check_set_max(p.max_app_program_len, &mut max_app_program_len);
    check_set_max(p.logic_sig_max_size as i32, &mut max_logic_sig_max_size);
    check_set_max(p.max_txn_note_bytes, &max_txn_note_bytes);
    check_set_max(p.max_tx_group_size, &max_tx_group_size);
    // max_bytes_key_value_len is max of max_app_key_len and max_app_bytes_value_len
    check_set_max(p.max_app_key_len, &max_bytes_key_value_len);
    check_set_max(p.max_app_bytes_value_len, &max_bytes_key_value_len);
    check_set_max(p.max_extra_app_program_pages, &max_extra_app_program_len);
    // max_available_app_program_len is the max of supported app program size
    max_available_app_program_len = max_app_program_len * (1 + max_extra_app_program_len);
    // There is no consensus parameter for max_log_calls and max_app_program_len as an approximation
    // Its value is much larger than any possible reasonable max_log_calls value in future
    check_set_max(p.max_app_program_len, &max_log_calls);
    check_set_max(p.max_inner_transactions, &max_inner_transactions);
}

/// Saves the configurable protocols file to the provided data directory.
/// If the params contain zero protocols, the existing consensus.json file will be removed if exists.
pub fn save_configurable_consensus(data_dir: &str, params: ConsensusProtocols) -> Result<()> {
    let consensus_protocol_path =
        Path::new(data_dir).join(super::CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);

    if params.len() == 0 {
        // We have no consensus params to write.
        // In this case, delete the existing file (if any).
        let err = std::fs::remove_file(consensusProtocolPath)?;
    }
    let encoded_consensus_params = json.Marshal(params);
    if err != nil {
        return err;
    }
    err = ioutil.WriteFile(consensusProtocolPath, encodedConsensusParams, 0o644);
    return err;
}

impl ConsensusProtocols {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Merges a configurable consensus ontop of the existing consensus protocol and returns
    /// a new consensus protocol without modifying any of the incoming structures.
    pub fn merge(&mut self, configurable_consensus: Self) -> Self {
        let static_consensus = self.clone();

        for (version, params) in configurable_consensus.0 {
            if params.approved_upgrades.len() == 0 {
                // if we were provided with an empty ConsensusParams,
                // delete the existing reference to this consensus version
                for (ver, par) in static_consensus.0 {
                    if ver == version {
                        static_consensus.0.remove(ver);
                    } else if par.approved_upgrades.contains_key(version) {
                        // delete upgrade to deleted version
                        par.approved_upgrades.remove(version);
                    }
                }
            } else {
                // need to add/update entry
                static_consensus.0[version] = params;
            }
        }

        return static_consensus;
    }
}

// Cloning creates a deep copy of a consensus protocols map.
// TODO can't we just derive Clone???
/*impl Clone for ConsensusProtocols {
    fn clone(&self) -> Self {
        let static_consensus = ConsensusProtocols::new();
        for consensusVersion, consensusParams := range cp {
            // recreate the ApprovedUpgrades map since we don't want to modify the original one.
            if consensusParams.ApprovedUpgrades != nil {
                newApprovedUpgrades := make(map[protocol.ConsensusVersion]uint64)
                for ver, when := range consensusParams.ApprovedUpgrades {
                    newApprovedUpgrades[ver] = when
                }
                consensusParams.ApprovedUpgrades = newApprovedUpgrades
            }
            staticConsensus[consensusVersion] = consensusParams
        }
        return static_consensus;
    }
}*/

/// Loads the configurable protocols from the data directory.
pub fn load_configurable_consensus_protocols(
    data_dir: &str,
    Consensus: &mut ConsensusProtocols,
) -> io::Result<()> {
    let new_consensus = preload_configurable_consensus_protocols(data_dir, Consensus)?;
    if new_consensus.len() > 0 {
        *Consensus = new_consensus;
        // Set allocation limits
        for (_, p) in Consensus.0 {
            check_set_alloc_bounds(p);
        }
    }
    return Ok(());
}

/// Loads the configurable protocols from the data directory and merges it with a copy of the Consensus map.
/// Finally, it returns it to the caller.
pub fn preload_configurable_consensus_protocols(
    data_dir: &str,
    Consensus: &ConsensusProtocols,
) -> Result<ConsensusProtocols> {
    let consensus_protocol_path =
        Path::new(data_dir).join(super::CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME);

    match std::fs::File::open(consensus_protocol_path) {
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => Ok(Consensus.clone()),
            _ => Err(e.into()),
        },
        Ok(file) => {
            let configurable_consensus = serde_json::from_reader(file)?;
            return Ok(Consensus.merge(configurable_consensus));
        }
    }
}

fn init_consensus_protocols(Consensus: &mut ConsensusProtocols) {
    // WARNING: copying a ConsensusParams by value into a new variable does not copy the ApprovedUpgrades map.
    // Make sure that each new ConsensusParams structure gets a fresh ApprovedUpgrades map.

    /// Base consensus protocol version, v7.
    let mut v7 = ConsensusParams {
        upgrade_vote_rounds: 10_000,
        upgrade_threshold: 9000,
        default_upgrade_wait_rounds: 10000,
        max_version_string_len: 64,

        min_balance: 10_000,
        min_txn_fee: 1000,
        max_txn_life: 1000,
        max_txn_note_bytes: 1024,
        max_txn_bytes_per_block: 1_000_000,
        default_key_dilution: 10_000,

        max_timestamp_increment: 25,

        reward_unit: 1_000_000,
        rewards_rate_refresh_interval: 500_000,

        approved_upgrades: HashMap::new(),

        num_proposers: 30,
        soft_committee_size: 2500,
        soft_committee_threshold: 1870,
        cert_committee_size: 1000,
        cert_committee_threshold: 720,
        next_committee_size: 10_000,
        next_committee_threshold: 7750,
        late_committee_size: 10_000,
        late_committee_threshold: 7750,
        redo_committee_size: 10_000,
        redo_committee_threshold: 7750,
        down_committee_size: 10_000,
        down_committee_threshold: 7750,

        agreement_filter_timeout: Duration::from_secs(4),
        agreement_filter_timeout_period0: Duration::from_secs(4),

        fast_recovery_lambda: Duration::from_secs(5 * 60),

        seed_lookback: 2,
        seed_refresh_interval: 100,

        max_bal_lookback: 320,

        max_tx_group_size: 1,
    };

    v7.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V7] = v7;

    // v8 uses parameters and a seed derivation policy (the "twin seeds") from Georgios' new analysis
    let mut v8 = v7;

    v8.seed_refresh_interval = 80;
    v8.num_proposers = 9;
    v8.soft_committee_size = 2990;
    v8.soft_committee_threshold = 2267;
    v8.cert_committee_size = 1500;
    v8.cert_committee_threshold = 1112;
    v8.next_committee_size = 5000;
    v8.next_committee_threshold = 3838;
    v8.late_committee_size = 5000;
    v8.late_committee_threshold = 3838;
    v8.redo_committee_size = 5000;
    v8.redo_committee_threshold = 3838;
    v8.down_committee_size = 5000;
    v8.down_committee_threshold = 3838;

    v8.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V8] = v8;

    // v7 can be upgraded to v8.
    v7.approved_upgrades[protocol::CONSENSUS_V8] = 0;

    // v9 increases the minimum balance to 100,000 micro_algos.
    let mut v9 = v8;
    v9.min_balance = 100_000;
    v9.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V9] = v9;

    // v8 can be upgraded to v9.
    v8.approved_upgrades[protocol::CONSENSUS_V9] = 0;

    // v10 introduces fast partition recovery (and also raises num_proposers).
    let mut v10 = v9;
    v10.fast_partition_recovery = true;
    v10.num_proposers = 20;
    v10.late_committee_size = 500;
    v10.late_committee_threshold = 320;
    v10.redo_committee_size = 2400;
    v10.redo_committee_threshold = 1768;
    v10.down_committee_size = 6000;
    v10.down_committee_threshold = 4560;
    v10.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V10] = v10;

    // v9 can be upgraded to v10.
    v9.approved_upgrades[protocol::CONSENSUS_V10] = 0;

    // v11 introduces signed_txn_in_block.
    let mut v11 = v10;
    v11.support_signed_txn_in_block = true;
    v11.payset_commit = payset_commit_flat;
    v11.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V11] = v11;

    // v10 can be upgraded to v11.
    v10.approved_upgrades[protocol::CONSENSUS_V11] = 0;

    // v12 increases the maximum length of a version string.
    let mut v12 = v11;
    v12.max_version_string_len = 128;
    v12.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V12] = v12;

    // v11 can be upgraded to v12.
    v11.approved_upgrades[protocol::CONSENSUS_V12] = 0;

    // v13 makes the consensus version a meaningful string.
    let mut v13 = v12;
    v13.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V13] = v13;

    // v12 can be upgraded to v13.
    v12.approved_upgrades[protocol::CONSENSUS_V13] = 0;

    // v14 introduces tracking of closing amounts in apply_data, and enables
    // genesis_hash in transactions.
    let mut v14 = v13;
    v14.apply_data = true;
    v14.support_genesis_hash = true;
    v14.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V14] = v14;

    // v13 can be upgraded to v14.
    v13.approved_upgrades[protocol::CONSENSUS_V14] = 0;

    // v15 introduces tracking of reward distributions in apply_data.
    let mut v15 = v14;
    v15.rewards_in_apply_data = true;
    v15.force_non_participating_fee_sink = true;
    v15.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V15] = v15;

    // v14 can be upgraded to v15.
    v14.approved_upgrades[protocol::CONSENSUS_V15] = 0;

    // v16 fixes domain separation in credentials.
    let mut v16 = v15;
    v16.credential_domain_separation_enabled = true;
    v16.require_genesis_hash = true;
    v16.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V16] = v16;

    // v15 can be upgraded to v16.
    v15.approved_upgrades[protocol::CONSENSUS_V16] = 0;

    // consensus_v17 points to 'final' spec commit
    let mut v17 = v16;
    v17.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V17] = v17;

    // v16 can be upgraded to v17.
    v16.approved_upgrades[protocol::CONSENSUS_V17] = 0;

    // consensus_v18 points to reward calculation spec commit
    let mut v18 = v17;
    v18.pending_residue_rewards = true;
    v18.approved_upgrades = HashMap::new();
    v18.txn_counter = true;
    v18.Asset = true;
    v18.logic_sig_version = 1;
    v18.logic_sig_max_size = 1000;
    v18.logic_sig_max_cost = 20_000;
    v18.max_assets_per_account = 1000;
    v18.support_tx_groups = true;
    v18.max_tx_group_size = 16;
    v18.support_transaction_leases = true;
    v18.support_become_non_participating_transactions = true;
    v18.max_asset_name_bytes = 32;
    v18.max_asset_unit_name_bytes = 8;
    v18.max_asset_uRLBytes = 32;
    Consensus.0[protocol::CONSENSUS_V18] = v18;

    // consensus_v19 is the official spec commit (teal, assets, group tx)
    let mut v19 = v18;
    v19.approved_upgrades = HashMap::new();

    Consensus.0[protocol::CONSENSUS_V19] = v19;

    // v18 can be upgraded to v19.
    v18.approved_upgrades[protocol::CONSENSUS_V19] = 0;
    // v17 can be upgraded to v19.
    v17.approved_upgrades[protocol::CONSENSUS_V19] = 0;

    // v20 points to adding the precision to the assets.
    let mut v20 = v19;
    v20.approved_upgrades = HashMap::new();
    v20.max_asset_decimals = 19;
    // we want to adjust the upgrade time to be roughly one week.
    // one week, in term of rounds would be:
    // 140651 = (7 * 24 * 60 * 60 / 4.3)
    // for the sake of future manual calculations, we'll round that down
    // a bit :
    v20.default_upgrade_wait_rounds = 140_000;
    Consensus.0[protocol::CONSENSUS_V20] = v20;

    // v19 can be upgraded to v20.
    v19.approved_upgrades[protocol::CONSENSUS_V20] = 0;

    // v21 fixes a bug in Credential.lowest_output that would cause larger accounts to be selected to propose
    // disproportionately more often than small accounts
    let mut v21 = v20;
    v21.approved_upgrades = HashMap::new();
    Consensus.0[protocol::CONSENSUS_V21] = v21;
    // v20 can be upgraded to v21.
    v20.approved_upgrades[protocol::CONSENSUS_V21] = 0;

    // v22 is an upgrade which allows tuning the number of rounds to wait to execute upgrades.
    let mut v22 = v21;
    v22.approved_upgrades = HashMap::new();
    v22.min_upgrade_wait_rounds = 10_000;
    v22.max_upgrade_wait_rounds = 150_000;
    Consensus.0[protocol::CONSENSUS_V22] = v22;

    // v23 is an upgrade which fixes the behavior of leases so that
    // it conforms with the intended spec.
    let mut v23 = v22;
    v23.approved_upgrades = HashMap::new();
    v23.fix_transaction_leases = true;
    Consensus.0[protocol::CONSENSUS_V23] = v23;
    // v22 can be upgraded to v23.
    v22.approved_upgrades[protocol::CONSENSUS_V23] = 10_000;
    // v21 can be upgraded to v23.
    v21.approved_upgrades[protocol::CONSENSUS_V23] = 0;

    // v24 is the stateful teal and rekeying upgrade
    let mut v24 = v23;
    v24.approved_upgrades = HashMap::new();
    v24.logic_sig_version = 2;

    // Enable application support
    v24.Application = true;

    // Enable rekeying
    v24.support_rekeying = true;

    // 100.1 Algos (= min_balance for creating 1,000 assets)
    v24.maximum_minimum_balance = 100_100_000;

    v24.max_app_args = 16;
    v24.max_app_total_arg_len = 2048;
    v24.max_app_program_len = 1024;
    v24.max_app_total_program_len = 2048; // No effect until v28, when max_app_program_len increased
    v24.max_app_key_len = 64;
    v24.max_app_bytes_value_len = 64;
    v24.max_app_sum_key_value_lens = 128; // Set here to have no effect until max_app_bytes_value_len increases

    // 0.1 Algos (Same min balance cost as an Asset)
    v24.app_flat_params_min_balance = 100_000;
    v24.app_flat_opt_in_min_balance = 100_000;

    // Can look up Sender + 4 other balance records per Application txn
    v24.max_app_txn_accounts = 4;

    // Can look up 2 other app creator balance records to see global state
    v24.max_app_txn_foreign_apps = 2;

    // Can look up 2 assets to see asset parameters
    v24.max_app_txn_foreign_assets = 2;

    // Intended to have no effect in v24 (it's set to accounts + asas + apps).
    // In later vers, it allows increasing the individual limits while maintaining same max references.
    v24.max_app_total_txn_references = 8;

    // 64 byte keys @ ~333 micro_algos/byte + delta
    v24.schema_min_balance_per_entry = 25_000;

    // 9 bytes @ ~333 micro_algos/byte + delta
    v24.schema_uint_min_balance = 3500;

    // 64 byte values @ ~333 micro_algos/byte + delta
    v24.schema_bytes_min_balance = 25000;

    // Maximum number of key/value pairs per local key/value store
    v24.max_local_schema_entries = 16;

    // Maximum number of key/value pairs per global key/value store
    v24.max_global_schema_entries = 64;

    // Maximum cost of approval_program/clear_state_program
    v24.max_app_program_cost = 700;

    // Maximum number of apps a single account can create
    v24.max_apps_created = 10;

    // Maximum number of apps a single account can opt into
    v24.max_apps_opted_in = 10;
    Consensus.0[protocol::CONSENSUS_V24] = v24;

    // v23 can be upgraded to v24, with an update delay of 7 days (see calculation above)
    v23.approved_upgrades[protocol::CONSENSUS_V24] = 140_000;

    // v25 enables asset_close_amount in the apply_data
    let mut v25 = v24;
    v25.approved_upgrades = HashMap::new();

    // Enable asset_close_amount field
    v25.enable_asset_close_amount = true;
    Consensus.0[protocol::CONSENSUS_V25] = v25;

    // v26 adds support for teal3
    let mut v26 = v25;
    v26.approved_upgrades = HashMap::new();

    // Enable the initial_rewards_rate_calculation fix
    v26.initial_rewards_rate_calculation = true;

    // Enable transaction Merkle tree.
    v26.payset_commit = payset_commit_merkle;

    // Enable teal3
    v26.logic_sig_version = 3;

    Consensus.0[protocol::CONSENSUS_V26] = v26;

    // v25 or v24 can be upgraded to v26, with an update delay of 7 days ( see calculation above )
    v25.approved_upgrades[protocol::CONSENSUS_V26] = 140_000;
    v24.approved_upgrades[protocol::CONSENSUS_V26] = 140_000;

    // v27 updates apply_delta.eval_delta.local_deltas format
    let mut v27 = v26;
    v27.approved_upgrades = HashMap::new();

    // Enable the apply_delta.eval_delta.local_deltas fix
    v27.no_empty_local_deltas = true;

    Consensus.0[protocol::CONSENSUS_V27] = v27;

    // v26 can be upgraded to v27, with an update delay of 3 days
    // 60279 = (3 * 24 * 60 * 60 / 4.3)
    // for the sake of future manual calculations, we'll round that down
    // a bit :
    v26.approved_upgrades[protocol::CONSENSUS_V27] = 60_000;

    // v28 introduces new TEAL features, larger program size, fee pooling and longer asset max URL
    let mut v28 = v27;
    v28.approved_upgrades = HashMap::new();

    // Enable TEAL 4 / AVM 0.9
    v28.logic_sig_version = 4;
    // Enable support for larger app program size
    v28.max_extra_app_program_pages = 3;
    v28.max_app_program_len = 2048;
    // Increase asset URL length to allow for IPFS URLs
    v28.max_asset_uRLBytes = 96;
    // Let the bytes value take more space. Key+Value is still limited to 128
    v28.max_app_bytes_value_len = 128;

    // Individual limits raised
    v28.max_app_txn_foreign_apps = 8;
    v28.max_app_txn_foreign_assets = 8;

    // max_app_txn_accounts has not been raised yet.  It is already
    // higher (4) and there is a multiplicative effect in
    // "reachability" between accounts and creatables, so we
    // retain 4 x 4 as worst case.

    v28.enable_fee_pooling = true;
    v28.enable_keyreg_coherency_check = true;

    Consensus.0[protocol::CONSENSUS_V28] = v28;

    // v27 can be upgraded to v28, with an update delay of 7 days ( see calculation above )
    v27.approved_upgrades[protocol::CONSENSUS_V28] = 140_000;

    // v29 fixes application update by using extra_program_pages in size calculations
    let mut v29 = v28;
    v29.approved_upgrades = HashMap::new();

    // Enable extra_program_pages for application update
    v29.enable_extra_pages_on_app_update = true;

    Consensus.0[protocol::CONSENSUS_V29] = v29;

    // v28 can be upgraded to v29, with an update delay of 3 days ( see calculation above )
    v28.approved_upgrades[protocol::CONSENSUS_V29] = 60_000;

    // v30 introduces AVM 1.0 and TEAL 5, increases the app opt in limit to 50,
    // and allows costs to be pooled in grouped stateful transactions.
    let mut v30 = v29;
    v30.approved_upgrades = HashMap::new();

    // Enable TEAL 5 / AVM 1.0
    v30.logic_sig_version = 5;

    // Enable App calls to pool budget in grouped transactions
    v30.enable_app_cost_pooling = true;

    // Enable Inner Transactions, and set maximum number. 0 value is
    // disabled.  Value > 0 also activates storage of creatable IDs in
    // apply_data, as that is required to support REST API when inner
    // transactions are activated.
    v30.max_inner_transactions = 16;

    // Allow 50 app opt ins
    v30.max_apps_opted_in = 50;

    Consensus.0[protocol::CONSENSUS_V30] = v30;

    // v29 can be upgraded to v30, with an update delay of 7 days ( see calculation above )
    v29.approved_upgrades[protocol::CONSENSUS_V30] = 140_000;

    // consensus_future is used to test features that are implemented
    // but not yet released in a production protocol version.
    let mut v_future = v30;
    v_future.approved_upgrades = HashMap::new();

    // filter_timeout for period 0 should take a new optimized, configured value, need to revisit this later
    v_future.agreement_filter_timeout_period0 = Duration::from_secs(4);

    // Enable compact certificates.
    v_future.compact_cert_rounds = 128;
    v_future.compact_cert_top_voters = 1024 * 1024;
    v_future.compact_cert_voters_lookback = 16;
    v_future.compact_cert_weight_threshold = (1 << 32) * 30 / 100;
    v_future.compact_cert_sec_kQ = 128;

    Consensus.0[protocol::CONSENSUS_FUTURE] = v_future;
}

// Global defines global Algorand protocol parameters which should not be overridden.
pub struct Global {
    pub small_lambda: std::time::Duration, // min amount of time to wait for leader's credential (i.e., time to propagate one credential)
    pub big_lambda: std::time::Duration, // max amount of time to wait for leader's proposal (i.e., time to propagate one block)
}

// Protocol holds the global configuration settings for the agreement protocol,
// initialized with our current defaults. This is used across all nodes we create.
static protocol: Global = Global {
    small_lambda: std::time::Duration::from_millis(2000),
    big_lambda: std::time::Duration::from_secs(15),
};

/*fn init() {
    Consensus = ConsensusProtocols::new();

    init_consensus_protocols();

    // Set allocation limits
    for (_, p) in Consensus {
        check_set_alloc_bounds(p);
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn TestConsensusParams() {
        for (proto, params) in Consensus {
            // Our implementation of Payset.Commit() assumes that
            // SupportSignedTxnInBlock implies not PaysetCommitUnsupported.
            if params.SupportSignedTxnInBlock {
                assert_ne!(
                    params.PaysetCommit,
                    PaysetCommitType::Unsupported,
                    "Protocol {}: SupportSignedTxnInBlock with PaysetCommitUnsupported",
                    proto
                );
            }

            // ApplyData requires not PaysetCommitUnsupported.
            if params.ApplyData && params.PaysetCommit == PaysetCommitType::Unsupported {
                assert_ne!(
                    params.PaysetCommit,
                    PaysetCommitType::Unsupported,
                    "Protocol {}: ApplyData with PaysetCommitUnsupported",
                    proto
                );
            }
        }
    }

    /// Ensures that the upgrade window is a non-zero value, and confirm to be within the valid range.
    #[test]
    fn TestConsensusUpgradeWindow() {
        for (proto, params) in Consensus {
            assert!(
                params.max_upgrade_wait_rounds >= params.min_upgrade_wait_rounds,
                "Version {}",
                proto
            );
            for (version, delay) in params.approved_upgrades {
                let msg = format!("From {}\nTo {}", proto, version);
                if params.MinUpgradeWaitRounds != 0 || params.MaxUpgradeWaitRounds != 0 {
                    assert_ne!(delay, 0, "{}", msg);
                    assert!(delay >= params.MinUpgradeWaitRounds, "{}", msg);
                    assert!(delay <= params.MaxUpgradeWaitRounds, "{}", msg);
                } else {
                    assert_eq!(delay, 0, "{}", msg);
                }
            }
        }
    }
}
