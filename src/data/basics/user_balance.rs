// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::*;
use crate::config;
use crate::crypto::{self, hashable::Hashable};
use crate::protocol;

/// Delegation status of an account's `MicroAlgos`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// Indicates that the associated account receives rewards but does not participate in the consensus.
    Offline,

    Online,

    /// Indicates that the associated account neither participates in the consensus, nor receives rewards.
    /// Accounts that are marked as NotParticipating cannot change their status,
    /// but can receive and send Algos to other accounts.
    /// Two special accounts that are defined as `NotParticipating` are the incentive pool
    /// (also know as rewards pool) and the fee sink.
    /// These two accounts also have additional Algo transfer restrictions.
    NotParticipating,
}

impl Default for Status {
    fn default() -> Self {
        Status::Offline
    }
}

/// Rough estimate for the worst-case scenario we're going to have of the account data and address serialized.
/// This number is verified by the `test_encoded_account_data_size` function.
pub const MAX_ENCODED_ACCOUNT_DATA_SIZE: usize = 850_000;

/// Decoder limit of number of assets stored per account.
/// It's being verified by the unit test `test_encoded_account_allocation_bounds` to align
/// with `config.Consensus[protocol.ConsensusCurrentVersion].MaxAssetsPerAccount`; note that the decoded
/// parameter is used only for protecting the decoder against malicious encoded account data stream.
/// Protocol-specific constains would be tested once the decoding is complete.
const MAX_ENCODED_ASSETS_PER_ACCOUNT: usize = 1024;

/// Decoder limit for number of opted-in apps in a single account.
/// It is verified in `test_encoded_account_allocation_bounds` to align with
/// `config.Consensus[protocol.ConsensusCurrentVersion].MaxppsOptedIn`.
pub const MAX_ENCODED_APP_LOCAL_STATES: usize = 64;

/// Decoder limit for number of created apps in a single account.
/// It is verified in `test_encoded_account_allocation_bounds` to align with
/// `config.Consensus[protocol.ConsensusCurrentVersion].MaxAppsCreated`.
pub const MAX_ENCODED_APP_PARAMS: usize = 64;

/// Decoder limit for the length of a key/value store.
/// It is verified in `test_encoded_account_allocation_bounds` to align with
/// `config.Consensus[protocol.ConsensusCurrentVersion].MaxLocalSchemaEntries` and
/// `config.Consensus[protocol.ConsensusCurrentVersion].MaxGlobalSchemaEntries`.
pub const MAX_ENCODED_KEY_VALUE_ENTRIES: usize = 1024;

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Offline => write!(f, "Offline"),
            Status::Online => write!(f, "Online"),
            Status::NotParticipating => write!(f, "Not Participating"),
        }
    }
}

// UnmarshalStatus decodes string status value back to Status constant
impl TryFrom<&str> for Status {
    type Error = ();

    fn try_from(s: &str) -> Result<Self, ()> {
        match s {
            "Offline" => Ok(Status::Offline),
            "Online" => Ok(Status::Online),
            "Not Participating" => Ok(Status::NotParticipating),
            _ => Err(()),
        }
    }
}

/// Contains the data associated with a given address.
///
/// This includes the account balance, cryptographic public keys,
/// consensus delegation status, asset data, and application data.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AccountData {
    pub status: Status,
    pub micro_algos: MicroAlgos,

    /// RewardsBase is used to implement rewards.
    /// This is not meaningful for accounts with `Status::NotParticipating`.
    ///
    /// Every block assigns some amount of rewards (algos) to every
    /// participating account. The amount is the product of how much
    /// block.RewardsLevel increased from the previous block and
    /// how many whole `config.Protocol.RewardUnit` algos this
    /// account holds.
    ///
    /// For performance reasons, we do not want to walk over every
    /// account to apply these rewards to AccountData.micro_algos. Instead,
    /// we defer applying the rewards until some other transaction
    /// touches that participating account, and at that point, apply all
    /// of the rewards to the account's AccountData.micro_algos.
    ///
    /// For correctness, we need to be able to determine how many
    /// total algos are present in the system, including deferred
    /// rewards (deferred in the sense that they have not been
    /// reflected in the account's AccountData.MicroAlgos, as described
    /// above). To compute this total efficiently, we avoid
    /// compounding rewards (i.e., no rewards on rewards) until
    /// they are applied to AccountData.micro_algos.
    ///
    /// Mechanically, RewardsBase stores the block.RewardsLevel
    /// whose rewards are already reflected in AccountData.MicroAlgos.
    /// If the account is Status::Offline or Status::Online, its
    /// effective balance (if a transaction were to be issued
    /// against this account) may be higher, as computed by
    /// AccountData.Money(). That function calls
    /// AccountData.WithUpdatedRewards() to apply the deferred
    /// rewards to AccountData.micro_algos.
    pub rewards_base: u64,

    /// Tracks how many algos were given to this account since the account was first created.
    ///
    /// This field is updated along with `reward_base`;
    /// note that it won't answer the question "how many algos did I make in the past week".
    pub rewarded_micro_algos: MicroAlgos,

    pub vote_id: crypto::OTSVerifier,
    pub selection_id: crypto::VrfPublicKey,

    pub vote_first_valid: Round,
    pub vote_last_valid: Round,
    pub vote_key_dilution: u64,

    /// If this account created an asset, `asset_params` stores the parameters defining that asset.
    /// The params are indexed by the Index of the AssetID; the Creator is this account's address.
    ///
    /// An account with any asset in AssetParams cannot be closed, until the asset is destroyed.
    /// An asset can be destroyed if this account holds asset_params.total units
    /// of that asset (in the Assets array below).
    ///
    /// NOTE: do not modify this value in-place in existing AccountData
    /// structs; allocate a copy and modify that instead. AccountData
    /// is expected to have copy-by-value semantics.
    pub asset_params: HashMap<AssetIndex, AssetParams>,

    /// Set of assets that can be held by this account.
    /// Assets (i.e., slots in this map) are explicitly
    /// added and removed from an account by special transactions.
    /// The map is keyed by the AssetID, which is the address of
    /// the account that created the asset plus a unique counter
    /// to distinguish re-created assets.
    ///
    /// Each asset bumps the required `min_balance` in this account.
    ///
    /// An account that creates an asset must have its own asset
    /// in the Assets map until that asset is destroyed.
    ///
    /// NOTE: do not modify this value in-place in existing AccountData
    /// structs; allocate a copy and modify that instead.  AccountData
    /// is expected to have copy-by-value semantics.
    pub assets: HashMap<AssetIndex, AssetHolding>,

    /// Address against which signatures/multisigs/logicsigs should be checked.
    /// If empty, the address of the account whose AccountData this is is used.
    /// A transaction may change an account's AuthAddr to "re-key" the account.
    /// This allows key rotation, changing the members in a multisig, etc.
    pub auth_addr: Address,

    /// Stores the local states associated with any applications that this account has opted in to.
    pub app_local_states: HashMap<AppIndex, AppLocalState>,

    /// Stores the global parameters and state associated with any applications that this account has created.
    pub app_params: HashMap<AppIndex, AppParams>,

    /// Stores the sum of all of the local `StateSchema`s and global `StateSchema`s in this account
    /// (global for applications we created, local for applications we opted in to),
    /// so that we don't have to iterate over all of them to compute `min_balance`.
    pub total_app_schema: StateSchema,

    /// Stores the extra length in pages (MaxAppProgramLen bytes per page) requested for app program by this account.
    pub total_extra_app_pages: u32,
}

/// Stores the LocalState associated with an application.
/// It also stores a cached copy of the application's local `StateSchema` so that `min_balance` requirements may be computed:
///   1) without looking up the `AppParams`, and
///   2) even if the application has been deleted
#[derive(Clone, Serialize, Deserialize)]
pub struct AppLocalState {
    pub schema: StateSchema,
    pub key_value: TealKeyValue,
}

/// Stores the global information associated with an application.
#[derive(Clone, Serialize, Deserialize)]
pub struct AppParams {
    pub approval_program: Vec<u8>,
    pub clear_state_program: Vec<u8>,
    pub global_state: TealKeyValue,
    pub state_schemas: StateSchemas,
    pub extra_program_pages: u32,
}

/// Thin wrapper around the local `StateSchema` and the global `StateSchema`, since they are often needed together.
#[derive(Clone, Serialize, Deserialize)]
pub struct StateSchemas {
    pub local_state_schema: StateSchema,
    pub global_state_schema: StateSchema,
}

/*
/// Clone returns a copy of some AppParams that may be modified without
/// affecting the original
func (ap *AppParams) Clone() (res AppParams) {
    res = *ap
    res.ApprovalProgram = make([]byte, len(ap.ApprovalProgram))
    copy(res.ApprovalProgram, ap.ApprovalProgram)
    res.ClearStateProgram = make([]byte, len(ap.ClearStateProgram))
    copy(res.ClearStateProgram, ap.ClearStateProgram)
    res.GlobalState = ap.GlobalState.Clone()
    return
}

// Clone returns a copy of some AppLocalState that may be modified without
// affecting the original
func (al *AppLocalState) Clone() (res AppLocalState) {
    res = *al
    res.KeyValue = al.KeyValue.Clone()
    return
}
*/

/// Encapsulates meaningful details about a given account, for external consumption.
struct AccountDetail {
    pub address: Address,
    pub algos: MicroAlgos,
    pub status: Status,
}

/// Encapsulates meaningful details about the ledger's current token supply.
struct SupplyDetail {
    pub round: Round,
    pub total_money: MicroAlgos,
    pub online_money: MicroAlgos,
}

/// Encapsulates meaningful details about the current balances of the ledger, for external consumption.
struct BalanceDetail {
    pub round: Round,
    pub total_money: MicroAlgos,
    pub online_money: MicroAlgos,
    pub accounts: Vec<AccountDetail>,
}

/// Unique integer index of an asset that can be used to look up the creator of the asset,
/// whose balance record contains the `AssetParams`.
pub type AssetIndex = u64;

/// Unique integer index of an application that can be used to look up the creator of the application,
/// whose balance record contains the `AppParams`.
#[derive(Clone, Copy, Debug, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppIndex(pub u64);

/// Represents either an `AssetIndex` or `AppIndex`, which come from the same namespace of indices as each other
/// (both assets and apps are "creatables")
pub type CreatableIndex = u64;

/// Represents whether or not a given creatable is an application or an asset
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreatableType {
    /// The `CreatableType` corresponding to assets.
    AssetCreatable,

    /// The CreatableType corresponds to apps.
    AppCreatable,
}

/// Stores both the creator, whose balance record contains the asset/app parameters,
/// and the creatable index, which is the key into those parameters.
pub struct CreatableLocator {
    pub creatable_type: CreatableType,
    pub creator: Address,
    pub index: CreatableIndex,
}

/// Describes an asset held by an account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssetHolding {
    pub amount: u64,
    pub frozen: bool,
}

/// Describes the parameters of an asset.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetParams {
    /// Specifies the total number of units of this asset created.
    pub total: u64,

    /// Specifies the number of digits to display after the decimal place when displaying this asset.
    ///   0 - asset is not divisible
    ///   1 - asset divisible into tenths
    /// ... - and so on
    /// This value must be between 0 and 19.
    /// (inclusive).
    pub decimals: u32,

    /// Whether slots for this asset in user accounts are frozen by default or not.
    pub default_frozen: bool,

    /// Hint for the name of a unit of this asset.
    pub unit_name: String,

    /// Hint for the name of the asset.
    pub asset_name: String,

    /// Specifies a URL where more information about the asset can be retrieved.
    pub url: String,

    /// Commitment to some unspecified asset metadata.
    /// The format of this metadata is up to the application.
    pub metadata_hash: [u8; 32],

    /// Manager specifies an account that is allowed to change the non-zero addresses in this AssetParams.
    pub manager: Address,

    /// Account whose holdings of this asset should be reported as "not minted".
    pub reserve: Address,

    /// An account that is allowed to change the frozen state of holdings of this asset.
    pub freeze: Address,

    /// An account that is allowed to take units of this asset from any account.
    pub clawback: Address,
}

impl Hashable for AppIndex {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::APP_INDEX, self.0.to_be_bytes().to_vec())
    }
}

impl AppIndex {
    /// Yields the "app address" of the app.
    fn address(&self) -> Address {
        Address::new(crypto::hash_obj(self))
    }
}

impl AccountData {
    fn new(status: Status, algos: MicroAlgos) -> Self {
        Self {
            status,
            micro_algos: algos,
            ..Default::default()
        }
    }

    /// Returns the amount of `MicroAlgos` associated with the user's account.
    fn money(
        &self,
        proto: &config::ConsensusParams,
        rewards_level: u64,
    ) -> (MicroAlgos, MicroAlgos) {
        let e = self.with_updated_rewards(proto, rewards_level);
        (e.micro_algos, e.rewarded_micro_algos)
    }

    /// Computes the amount of rewards (in `MicroAlgos`) that have yet to be added to the account balance.
    // TODO track overflow? (see go-algorand)
    fn pending_rewards(
        &self,
        proto: config::ConsensusParams,
        micro_algos: MicroAlgos,
        rewards_base: u64,
        rewards_level: u64,
    ) -> MicroAlgos {
        let rewards_units = micro_algos.reward_units(&proto);
        let rewards_delta = rewards_level - rewards_base;
        MicroAlgos(rewards_units * rewards_delta)
    }

    /// Returns an updated number of algos in an `AccountData` to reflect rewards up to some rewards level.
    // TODO should copy self, or is it fine to mutate?
    fn with_updated_rewards(
        &self,
        proto: &config::ConsensusParams,
        rewards_level: u64,
    ) -> AccountData {
        let mut ad = self.clone();
        if ad.status != Status::NotParticipating {
            let rewards_units = ad.micro_algos.reward_units(proto);
            let rewards_delta = rewards_level - ad.rewards_base;
            let rewards = MicroAlgos(rewards_units * rewards_delta);
            ad.micro_algos = MicroAlgos(ad.micro_algos.0 + rewards.0);
            ad.rewards_base = rewards_level;
            // The total reward over the lifetime of the account could exceed a 64-bit value. As a result
            // this reward_algos counter could potentially roll over.
            ad.rewarded_micro_algos = MicroAlgos(ad.rewarded_micro_algos.0.wrapping_add(rewards.0));
        }

        ad
    }

    /// Computes the minimum balance requirements for an account based on some consensus parameters.
    /// `min_balance` should correspond roughly to how much storage the account is allowed to store on disk.
    fn min_balance(&self, proto: &config::ConsensusParams) -> MicroAlgos {
        // First, base min balance
        let mut min = proto.min_balance;

        // min balance for each Asset
        let asset_cost = proto.min_balance.saturating_mul(self.assets.len() as u64);
        min = min.saturating_add(asset_cost);

        // Base min balance for each created application
        let app_creation_cost = proto
            .app_flat_params_min_balance
            .saturating_mul(self.app_params.len() as u64);
        min = min.saturating_add(app_creation_cost);

        // Base min balance for each opted in application
        let app_opt_in_cost = proto
            .app_flat_opt_in_min_balance
            .saturating_mul(self.app_local_states.len() as u64);
        min = min.saturating_add(app_opt_in_cost);

        // min balance for state usage measured by LocalStateSchemas and
        // GlobalStateSchemas
        let schema_cost = self.total_app_schema.min_balance(proto);
        min = min.saturating_add(schema_cost.to_u64());

        // min balance for each extra app program page
        let extra_app_program_len_cost = proto
            .app_flat_params_min_balance
            .saturating_mul(self.total_extra_app_pages as u64);
        min = min.saturating_add(extra_app_program_len_cost);

        MicroAlgos(min)
    }

    /// Returns the amount of `MicroAlgos` associated with the user's account
    /// for the purpose of participating in the Algorand protocol.
    /// It assumes the caller has already updated rewards appropriately using `with_updated_rewards()`.
    pub fn voting_stake(&self) -> MicroAlgos {
        match self.status {
            Status::Online => self.micro_algos,
            _ => MicroAlgos(0),
        }
    }

    /// Returns the key dilution for this account, returning the default key dilution if not explicitly specified.
    fn key_dilution(&self, proto: config::ConsensusParams) -> u64 {
        match self.vote_key_dilution {
            0 => proto.default_key_dilution,
            _ => self.vote_key_dilution,
        }
    }

    /*
    /// Checks if an AccountData value is the same as its zero value.
    fn is_zero(&self) -> bool {
        *self == AccountData::default()
    }
    */

    /// Returns a ``normalized'' balance for this account.
    ///
    /// The normalization compensates for rewards that have not yet been applied,
    /// by computing a balance normalized to round 0.  To normalize, we estimate
    /// the microalgo balance that an account should have had at round 0, in order
    /// to end up at its current balance when rewards are included.
    ///
    /// The benefit of the normalization procedure is that an account's normalized
    /// balance does not change over time (unlike the actual algo balance that includes
    /// rewards).  This makes it possible to compare normalized balances between two
    /// accounts, to sort them, and get results that are close to what we would get
    /// if we computed the exact algo balance of the accounts at a given round number.
    ///
    /// The normalization can lead to some inconsistencies in comparisons between
    /// account balances, because the growth rate of rewards for accounts depends
    /// on how recently the account has been touched (our rewards do not implement
    /// compounding).  However, online accounts have to periodically renew
    /// participation keys, so the scale of the inconsistency is small.
    fn normalized_online_balance(&self, proto: config::ConsensusParams) -> u64 {
        if self.status != Status::Online {
            return 0;
        }

        // If this account had one RewardUnit of microAlgos in round 0,
        // it would have per_reward_unit microAlgos at the account's current rewards level.
        let per_reward_unit = self.rewards_base + proto.reward_unit;

        // To normalize, we compute, mathematically,
        // `u.MicroAlgos / perRewardUnit * proto.RewardUnit`, as
        // `(u.MicroAlgos * proto.RewardUnit) / perRewardUnit`.
        //norm, overflowed = Muldiv(self.micro_algos.to_u64(), proto.reward_unit, per_reward_unit)?
        let norm = self.micro_algos.to_u64().checked_mul(proto.reward_unit);

        // Mathematically should be impossible to overflow because `per_reward_unit >= proto.reward_unit`,
        // as long as `self.reward_base` isn't huge enough to cause overflow.
        if norm.is_none() {
            // TODO use logger
            panic!(
                "overflow computing normalized balance {} * {} / ({} + {})",
                self.micro_algos.to_u64(),
                proto.reward_unit,
                self.rewards_base,
                proto.reward_unit
            );
        }

        match norm.unwrap().checked_div(per_reward_unit) {
            // Mathematically should be impossible to overflow because `per_reward_unit >= proto.reward_unit`,
            // as long as `self.reward_base` isn't huge enough to cause overflow.
            None => {
                // TODO use logger
                panic!(
                    "overflow computing normalized balance {} * {} / ({} + {})",
                    self.micro_algos.to_u64(),
                    proto.reward_unit,
                    self.rewards_base,
                    proto.reward_unit
                );
            }
            Some(n) => n,
        }
    }
}

/// Pairs an account's address with its associated data.
#[derive(Default, Serialize, Deserialize)]
struct BalanceRecord {
    pub addr: Address,
    pub account_data: AccountData,
}

impl Hashable for BalanceRecord {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        // TODO implement protocol::codec
        //(protocol::BALANCE_RECORD, protocol::encode(&self))
        (protocol::BALANCE_RECORD, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::basics::MicroAlgos;

    // TODO add again once encode is fixed for ommitting empty values
    /*
    #[test]
    fn empty_encoding() {
        let ub = BalanceRecord::default();
        assert_eq!(protocol::encode(&ub).len(), 1);
    }
    */

    #[test]
    fn rewards() {
        let proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
        let account_algos = vec![
            MicroAlgos(0),
            MicroAlgos(8000),
            MicroAlgos(13000),
            MicroAlgos(83000),
        ];
        for algos in account_algos {
            let ad = AccountData {
                status: Status::Online,
                micro_algos: algos,
                rewards_base: 100,
                rewarded_micro_algos: MicroAlgos(25),
                ..Default::default()
            };

            let levels = vec![0, 1, 30, 3000];
            for level in levels {
                let (money, rewards) = ad.money(proto, ad.rewards_base + level);
                assert_eq!(
                    money.0,
                    ad.micro_algos.0 + level * ad.micro_algos.reward_units(proto)
                );
                assert_eq!(
                    rewards.0,
                    ad.rewarded_micro_algos.0 + level * ad.micro_algos.reward_units(proto)
                );
            }
        }
    }

    #[test]
    #[should_panic]
    fn with_updated_rewards_overflow() {
        let proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
        let a = AccountData {
            status: Status::Online,
            micro_algos: MicroAlgos(!0),
            rewarded_micro_algos: MicroAlgos(0),
            rewards_base: 0,
            ..Default::default()
        };
        a.with_updated_rewards(proto, 100);
    }

    #[test]
    fn with_updated_rewards_wrapping() {
        let proto = &config::CONSENSUS.0[&protocol::CURRENT_CONSENSUS_VERSION];
        let a = AccountData {
            status: Status::Online,
            micro_algos: MicroAlgos(80_000_000),
            rewarded_micro_algos: MicroAlgos(!0),
            rewards_base: 0,
            ..Default::default()
        };
        let b = a.with_updated_rewards(proto, 100);
        assert_eq!(
            b.rewarded_micro_algos.0,
            100 * a.micro_algos.reward_units(proto) - 1
        );
    }

    // TODO port TestEncodedAccountDataSize from go-algorand once encoding works

    #[test]
    fn encoded_account_allocation_bounds() {
        // ensure that all the supported protocols have value limits less or
        // equal to their corresponding codec allocbounds
        for (proto_ver, proto) in &config::CONSENSUS.0 {
            if proto.max_assets_per_account as u64 > MAX_ENCODED_ASSETS_PER_ACCOUNT as u64 {
                panic!("failed for protocol version {}", proto_ver)
            }
            if proto.max_apps_created as u64 > MAX_ENCODED_APP_PARAMS as u64 {
                panic!("failed for protocol version {}", proto_ver)
            }
            if proto.max_apps_opted_in as u64 > MAX_ENCODED_APP_LOCAL_STATES as u64 {
                panic!("failed for protocol version {}", proto_ver)
            }
            if proto.max_local_schema_entries as u64 > MAX_ENCODED_KEY_VALUE_ENTRIES as u64 {
                panic!("failed for protocol version {}", proto_ver)
            }
            if proto.max_global_schema_entries as u64 > MAX_ENCODED_KEY_VALUE_ENTRIES as u64 {
                panic!("failed for protocol version {}", proto_ver)
            }
        }
    }

    #[test]
    fn app_index_hashing() {
        let i = AppIndex(12);
        let (prefix, buf) = i.to_be_hashed();
        assert_eq!(prefix, protocol::APP_INDEX);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c]);

        let i = AppIndex(12 << 16);
        let (prefix, buf) = i.to_be_hashed();
        assert_eq!(prefix, protocol::APP_INDEX);
        assert_eq!(buf, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00]);

        // test value from go-algorand
        let i = AppIndex(77);
        assert_eq!(
            i.address().to_string(),
            "PCYUFPA2ZTOYWTP43MX2MOX2OWAIAXUDNC2WFCXAGMRUZ3DYD6BWFDL5YM",
        );
    }
}
