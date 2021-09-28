// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryFrom;
use std::fmt;

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

use super::*;
use crate::config;
use crate::crypto::{self, hashable::*};
use crate::data::basics;
use crate::protocol;

/// A hash uniquely identifying individual transactions.
pub struct TxID(CryptoHash);

/// Prints TxID as a pretty-printable string.
impl fmt::Display for TxID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&str> for TxID {
    type Error = HashError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(TxID(CryptoHash::try_from(s)?))
    }
}

/// Holds addresses with non-standard properties.
pub struct SpecialAddresses {
    pub fee_sink: basics::Address,
    pub rewards_pool: basics::Address,
}

/// Captures the fields common to every transaction type.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub sender: basics::Address,
    pub fee: basics::MicroAlgos,
    pub first_valid: basics::Round,
    pub last_valid: basics::Round,
    pub note: Vec<u8>,
    pub genesis_id: String,
    pub genesis_hash: CryptoHash,

    /// Specifies that this transaction is part of a transaction group
    /// (and, if so, specifies the hash of the transaction group).
    pub group: CryptoHash,

    /// Enforces mutual exclusion of transactions.
    /// If this field is nonzero, then once the transaction is confirmed, it acquires the
    /// lease identified by the pair (sender, lease) until the last_valid round passes.
    /// While this transaction possesses the lease, no other transaction with this lease can be confirmed.
    pub lease: [u8; 32],

    /// If nonzero, sets the sender's `auth_addr` to the given address.
    /// If the `rekey_to` address is the sender's actual address, the `auth_addr` is set to zero.
    /// This allows "re-keying" a long-lived account -- rotating the signing key,
    /// changing membership of a multisig account, etc.
    pub rekey_to: basics::Address,
}

/// Describes a transaction that can appear in a block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transaction {
    Keyreg(Header, KeyregFields),
    Payment(Header, PaymentFields),
    AssetConfig(Header, AssetConfigFields),
    AssetTransfer(Header, AssetTransferFields),
    AssetFreeze(Header, AssetFreezeFields),
    AppCall(Header, AppCallFields),
    CompactCert(Header, CompactCertFields),
}

impl Hashable for Transaction {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::TRANSACTION, protocol::encode(self))
    }
}

/// Contains information about the transaction's execution.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyData {
    /// Closing amount for transaction.
    pub closing_amount: basics::MicroAlgos,

    /// Closing amount for asset transaction.
    pub asset_closing_amount: u64,

    // Rewards applied to the `sender`, `receiver`, and `close_remainder_to` accounts.
    pub sender_rewards: basics::MicroAlgos,
    pub receiver_rewards: basics::MicroAlgos,
    pub close_rewards: basics::MicroAlgos,
    pub eval_delta: EvalDelta,

    // If asa or app is being created, the id used. Else 0.
    // Names chosen to match naming the corresponding txn.
    // These are populated on when MaxInnerTransactions > 0 (TEAL 5)
    pub config_asset: basics::AssetIndex,
    pub application_id: basics::AppIndex,
}

/// Describes a group of transactions that must appear together in a specific order in a block.
#[derive(Serialize, Deserialize)]
struct TxGroup {
    /// Specifies a list of hashes of transactions that must appear
    /// together, sequentially, in a block in order for the group to be
    /// valid.  Each hash in the list is a hash of a transaction with
    /// the `Group` field omitted.
    pub tx_group_hashes: Vec<CryptoHash>,
}

impl Hashable for TxGroup {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::TX_GROUP, protocol::encode(self))
    }
}

impl Header {
    /// Checks to see if the transaction is still alive (can be applied) at the specified Round.
    fn alive(&self, tc: &impl TxContext) -> Result<(), InvalidTx> {
        // Check round validity
        let round = tc.round();
        if round < self.first_valid || round > self.last_valid {
            return Err(InvalidTx::Dead {
                round,
                first_valid: self.first_valid,
                last_valid: self.last_valid,
            });
        }

        // Check genesis ID
        let proto = tc.consensus_protocol();
        let genesis_id = tc.genesis_id();
        if !self.genesis_id.is_empty() && self.genesis_id != genesis_id {
            return Err(InvalidTx::GenesisIdMismatch(
                self.genesis_id.clone(),
                genesis_id,
            ));
        }

        // Check genesis hash
        if proto.support_genesis_hash {
            let genesis_hash = tc.genesis_hash();
            if !self.genesis_hash.is_zero() && self.genesis_hash != genesis_hash {
                return Err(InvalidTx::GenesisHashMismatch(
                    self.genesis_hash.clone(),
                    genesis_hash,
                ));
            }
            if proto.require_genesis_hash && self.genesis_hash.is_zero() {
                return Err(InvalidTx::GenesisHashMissing);
            }
        } else if !self.genesis_hash.is_zero() {
            return Err(InvalidTx::GenesisHashNotAllowed);
        }

        Ok(())
    }
}

impl Transaction {
    /// Returns the TxID (i.e. cryptographic hash) of the transaction.
    pub fn id(&self) -> TxID {
        // TODO include protocol::TRANSACTION
        let enc = protocol::encode(self);
        TxID(hash(&enc))
    }

    /// Signs this transaction using a given account's secrets.
    pub fn sign(&self, kp: &crypto::Keypair) -> SignedTx {
        let sig = kp.sign(&self.hash_rep());
        let mut s = SignedTx {
            tx: self.clone(),
            sig,
            msig: None,
            lsig: None,
            auth_addr: Default::default(),
        };

        // Set the `auth_addr` if the signing key doesn't match the transaction sender.
        if basics::Address(kp.public.to_bytes()) != self.header().sender {
            s.auth_addr = basics::Address(kp.public.to_bytes());
        }

        s
    }

    pub fn header(&self) -> &Header {
        match self {
            Self::Keyreg(header, _) => header,
            Self::Payment(header, _) => header,
            Self::AssetConfig(header, _) => header,
            Self::AssetTransfer(header, _) => header,
            Self::AssetFreeze(header, _) => header,
            Self::AppCall(header, _) => header,
            Self::CompactCert(header, _) => header,
        }
    }

    /// Checks if the transaction involves a given address.
    fn match_address(&self, addr: basics::Address, spec: SpecialAddresses) -> bool {
        self.relevant_addrs(&spec).contains(&addr)
    }

    /// Checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger).
    /// It does not check signatures!
    pub fn is_well_formed(
        &self,
        spec: &SpecialAddresses,
        proto: &config::ConsensusParams,
    ) -> Result<(), InvalidTx> {
        match self {
            Self::Payment(header, fields) => {
                // In case that the fee sink is spending, check that this spend is to a valid address.
                fields.check_spender(header, spec, proto)?;
            }
            Self::Keyreg(header, fields) => {
                if proto.enable_keyreg_coherency_check {
                    fields.check_coherency(header)?;
                }

                // Check that, if this tx is marking an account nonparticipating,
                // it supplies no key (as though it were trying to go offline).
                if fields.nonparticipation {
                    if !proto.support_become_non_participating_transactions {
                        // if the transaction has the Nonparticipation flag high, but the protocol does not support
                        // that type of transaction, it is invalid.
                        return Err(InvalidTx::KeyregUnsupportedSwitchToNonParticipating);
                    }
                    let supplies_null_keys = fields.vote_pk == Default::default()
                        || fields.selection_pk == Default::default();
                    if !supplies_null_keys {
                        return Err(InvalidTx::KeyregGoingOnlineWithNonParticipating);
                    }
                }
            }
            Self::AssetConfig(_, _) | Self::AssetTransfer(_, _) | Self::AssetFreeze(_, _) => {
                if !proto.asset {
                    return Err(InvalidTx::AssetTxsNotSupported);
                }
            }
            Self::AppCall(_, fields) => {
                if !proto.application {
                    return Err(InvalidTx::AppTxsNotSupported);
                }

                // Programs may only be set for creation or update.
                if fields.application_id != basics::AppIndex(0)
                    && fields.on_completion != OnCompletion::UpdateApplicationOC
                    && (!fields.approval_program.is_empty()
                        || !fields.clear_state_program.is_empty())
                {
                    //return fmt.Errorf( "programs may only be specified during application creation or update",);
                    return Err(InvalidTx::Unknown);
                }

                let mut effective_epp = fields.extra_program_pages;
                // Schemas and ExtraProgramPages may only be set during application creation.
                if fields.application_id != basics::AppIndex(0) {
                    if fields.local_state_schema != Default::default()
                        || fields.global_state_schema != Default::default()
                    {
                        //return fmt.Errorf("local and global state schemas are immutable");
                        return Err(InvalidTx::Unknown);
                    }
                    if fields.extra_program_pages != 0 {
                        //return fmt.Errorf("tx.ExtraProgramPages is immutable");
                        return Err(InvalidTx::Unknown);
                    }

                    if proto.enable_extra_pages_on_app_update {
                        effective_epp = proto.max_extra_app_program_pages as u32
                    }
                }

                // Limit total number of arguments
                if fields.application_args.len() as u64 > proto.max_app_args as u64 {
                    //return fmt.Errorf("too many application args, max %d", proto.MaxAppArgs);
                    return Err(InvalidTx::Unknown);
                }

                // Sum up argument lengths
                let mut arg_sum = 0_u64;
                for arg in &fields.application_args {
                    arg_sum = arg_sum.saturating_add(arg.len() as u64);
                }

                // Limit total length of all arguments
                if arg_sum > proto.max_app_total_arg_len as u64 {
                    //return fmt.Errorf( "application args total length too long, max len %d bytes", proto.MaxAppTotalArgLen,);
                    return Err(InvalidTx::Unknown);
                }

                // Limit number of accounts referred to in a single ApplicationCall
                if fields.accounts.len() as u64 > proto.max_app_tx_accounts as u64 {
                    //return fmt.Errorf( "tx.Accounts too long, max number of accounts is %d", proto.MaxAppTxnAccounts,);
                    return Err(InvalidTx::Unknown);
                }

                // Limit number of other app global states referred to
                if fields.foreign_apps.len() as u64 > proto.max_app_tx_foreign_apps as u64 {
                    //return fmt.Errorf( "tx.ForeignApps too long, max number of foreign apps is %d", proto.MaxAppTxnForeignApps,);
                    return Err(InvalidTx::Unknown);
                }

                if fields.foreign_assets.len() as u64 > proto.max_app_tx_foreign_assets as u64 {
                    //return fmt.Errorf( "tx.ForeignAssets too long, max number of foreign assets is %d", proto.MaxAppTxnForeignAssets,);
                    return Err(InvalidTx::Unknown);
                }

                // Limit the sum of all types of references that bring in account records
                if (fields.accounts.len() as u64
                    + fields.foreign_apps.len() as u64
                    + fields.foreign_assets.len() as u64)
                    > proto.max_app_total_tx_references as u64
                {
                    //return fmt.Errorf( "tx has too many references, max is %d", proto.MaxAppTotalTxnReferences,);
                    return Err(InvalidTx::Unknown);
                }

                if fields.extra_program_pages > proto.max_extra_app_program_pages as u32 {
                    //return fmt.Errorf( "tx.ExtraProgramPages too large, max number of extra pages is %d", proto.MaxExtraAppProgramPages,);
                    return Err(InvalidTx::Unknown);
                }

                let ap_len = fields.approval_program.len();
                let cs_len = fields.clear_state_program.len();
                let pages = 1 + effective_epp;
                if ap_len as u64 > pages as u64 * proto.max_app_program_len as u64 {
                    //return fmt.Errorf( "approval program too long. max len %d bytes", pages * proto.MaxAppProgramLen,);
                    return Err(InvalidTx::Unknown);
                } else if cs_len as u64 > pages as u64 * proto.max_app_program_len as u64 {
                    //return fmt.Errorf( "clear state program too long. max len %d bytes", pages * proto.MaxAppProgramLen,);
                    return Err(InvalidTx::Unknown);
                } else if ap_len as u64 + cs_len as u64
                    > pages as u64 * proto.max_app_total_program_len as u64
                {
                    //return fmt.Errorf( "app programs too long. max total len %d bytes", pages * proto.MaxAppTotalProgramLen,);
                    return Err(InvalidTx::Unknown);
                } else if fields.local_state_schema.num_entries() > proto.max_local_schema_entries {
                    //return fmt.Errorf( "tx.LocalStateSchema too large, max number of keys is %d", proto.MaxLocalSchemaEntries,);
                    return Err(InvalidTx::Unknown);
                } else if fields.global_state_schema.num_entries() > proto.max_global_schema_entries
                {
                    //return fmt.Errorf( "tx.GlobalStateSchema too large, max number of keys is %d", proto.MaxGlobalSchemaEntries,);
                    return Err(InvalidTx::Unknown);
                }
            }
            Self::CompactCert(header, _) => {
                if proto.compact_cert_rounds == 0 {
                    return Err(InvalidTx::CompactcertTxsNotSupported);
                }

                // This is a placeholder transaction used to store compact certs on the ledger,
                // and ensure they are broadly available.
                // Most of the fields must be empty.
                // It must be issued from a special sender address.
                if header.sender != *COMPACT_CERT_SENDER {
                    //return fmt.Errorf("sender must be the compact-cert sender");
                    return Err(InvalidTx::Unknown);
                } else if !header.fee.is_zero() {
                    //return fmt.Errorf("fee must be zero");
                    return Err(InvalidTx::Unknown);
                } else if !header.note.is_empty() {
                    //return fmt.Errorf("note must be empty");
                    return Err(InvalidTx::Unknown);
                } else if !header.group.is_zero() {
                    //return fmt.Errorf("group must be zero");
                    return Err(InvalidTx::Unknown);
                } else if !header.rekey_to.is_zero() {
                    //return fmt.Errorf("rekey must be zero");
                    return Err(InvalidTx::Unknown);
                } else if header.lease != [0; 32] {
                    //return fmt.Errorf("lease must be zero");
                    return Err(InvalidTx::Unknown);
                }
            }
        }

        /*
        let non_zero_fields = make(map[protocol.TxType]bool); // TODO use HashSet
        if self.PaymentTxnFields != (PaymentTxnFields{}) {
            nonZeroFields[protocol.PaymentTx] = true
        }

        if self.KeyregTxnFields != (KeyregTxnFields{}) {
            nonZeroFields[protocol.KeyRegistrationTx] = true
        }

        if self.AssetConfigTxnFields != (AssetConfigTxnFields{}) {
            nonZeroFields[protocol.AssetConfigTx] = true
        }

        if self.AssetTransferTxnFields != (AssetTransferTxnFields{}) {
            nonZeroFields[protocol.AssetTransferTx] = true
        }

        if self.AssetFreezeTxnFields != (AssetFreezeTxnFields{}) {
            nonZeroFields[protocol.AssetFreezeTx] = true
        }

        if !self.ApplicationCallTxnFields.Empty() {
            nonZeroFields[protocol.ApplicationCallTx] = true
        }

        if !self.CompactCertTxnFields.Empty() {
            nonZeroFields[protocol.CompactCertTx] = true
        }

        for t, nonZero := range non_zero_fields {
            if nonZero && t != self.tx_ype {
                return fmt.Errorf("transaction of type %v has non-zero fields for type %v", tx.Type, t)
            }
        }
        */

        if !proto.enable_fee_pooling && self.header().fee <= basics::MicroAlgos(proto.min_tx_fee) {
            if let Self::CompactCert(_, _) = self {
                // Zero fee allowed for compact cert txn.
            } else {
                return Err(InvalidTx::FeeLessThanMin(
                    self.header().fee,
                    basics::MicroAlgos(proto.min_tx_fee),
                ));
            }
        }
        if self.header().last_valid < self.header().first_valid {
            return Err(InvalidTx::BadValidityRange(
                self.header().first_valid,
                self.header().last_valid,
            ));
        } else if self.header().last_valid.0 - self.header().first_valid.0 > proto.max_tx_life {
            return Err(InvalidTx::ExcessiveValidityRange(
                self.header().first_valid,
                self.header().last_valid,
            ));
        } else if self.header().note.len() as u64 > proto.max_tx_note_bytes as u64 {
            return Err(InvalidTx::NoteTooBig(
                self.header().note.len(),
                proto.max_tx_note_bytes,
            ));
        }

        if let Self::AssetConfig(_, fields) = self {
            if fields.asset_params.asset_name.len() as u64 > proto.max_asset_name_bytes as u64 {
                return Err(InvalidTx::AssetNameTooBig(
                    fields.asset_params.asset_name.len(),
                    proto.max_asset_name_bytes,
                ));
            } else if fields.asset_params.unit_name.len() as u64
                > proto.max_asset_unit_name_bytes as u64
            {
                return Err(InvalidTx::AssetUnitNameTooBig(
                    fields.asset_params.unit_name.len(),
                    proto.max_asset_unit_name_bytes,
                ));
            } else if fields.asset_params.url.len() as u64 > proto.max_asset_url_bytes as u64 {
                return Err(InvalidTx::AssetUrlTooBig(
                    fields.asset_params.url.len(),
                    proto.max_asset_url_bytes,
                ));
            } else if fields.asset_params.decimals > proto.max_asset_decimals {
                return Err(InvalidTx::AssetDecimalsTooHigh(
                    fields.asset_params.decimals,
                    proto.max_asset_decimals,
                ));
            }
        }

        if self.header().sender == spec.rewards_pool {
            // this check is just to be safe, but reaching here seems impossible, since it requires computing a preimage of rwpool
            unreachable!("transaction from incentive pool");
        } else if self.header().sender.is_zero() {
            Err(InvalidTx::ZeroSender)
        } else if !proto.support_transaction_leases && (self.header().lease != [0; 32]) {
            Err(InvalidTx::LeasesNotSupported)
        } else if !proto.support_tx_groups && (!self.header().group.is_zero()) {
            Err(InvalidTx::GroupsNotSupported)
        } else if !proto.support_rekeying && (!self.header().rekey_to.is_zero()) {
            Err(InvalidTx::RekeyingNotSupported)
        } else {
            Ok(())
        }
    }

    /// Returns the addresses whose balance records this transaction will need to access.
    /// The header's default is to return just the sender and the fee sink.
    fn relevant_addrs(&self, spec: &SpecialAddresses) -> Vec<basics::Address> {
        let mut addrs = vec![self.header().sender, spec.fee_sink];

        match self {
            Self::Payment(_, fields) => {
                addrs.push(fields.receiver);
                if let Some(close_to) = fields.close_remainder_to {
                    addrs.push(close_to);
                }
            }
            Self::AssetTransfer(_, fields) => {
                addrs.push(fields.asset_receiver);
                if !fields.asset_close_to.is_zero() {
                    addrs.push(fields.asset_close_to);
                }
                if !fields.asset_sender.is_zero() {
                    addrs.push(fields.asset_sender);
                }
            }
            _ => {}
        };

        addrs
    }

    /// Returns the amount paid to the recipient in this payment.
    fn tx_amount(&self) -> basics::MicroAlgos {
        match self {
            Self::Payment(_, fields) => fields.amount,
            _ => basics::MicroAlgos(0),
        }
    }

    /// Returns the address of the receiver. If the transaction has no receiver, it returns the empty address.
    fn get_receiver_rddress(&self) -> Option<basics::Address> {
        match self {
            Self::Payment(_, fields) => Some(fields.receiver),
            Self::AssetTransfer(_, fields) => Some(fields.asset_receiver),
            _ => None,
        }
    }

    /// Returns the estimated encoded size of the transaction including the signature.
    /// This function is to be used for calculating the fee.
    /// Note that it may be an underestimate if the transaction is signed in an unusual way
    /// (e.g., with an authaddr or via multisig or logicsig).
    pub fn estimate_encoded_size(&self) -> usize {
        // Make a signed transaction with a nonzero signature and encode it.
        // TODO make Transaction impl Clone or let SignedTx use &Transaction
        /*let stx = SignedTx {
            tx: self.clone(),
            sig: crypto::Signature::new([1; crypto::SIGNATURE_LENGTH]),
        };
        return stx.get_encoded_length();*/
        200
    }
}

/// Describes the context in which a transaction can appear (pretty much, a block,
/// but we don't have the definition of a block here, since that would be a circular dependency).
/// This is used to decide if a transaction is alive or not.
trait TxContext {
    fn round(&self) -> basics::Round;
    fn consensus_protocol(&self) -> config::ConsensusParams;
    fn genesis_id(&self) -> String;
    fn genesis_hash(&self) -> CryptoHash;
}

/// An instantiation of the TxContext trait with explicit fields for everything.
struct ExplicitTxContext {
    explicit_round: basics::Round,
    proto: config::ConsensusParams,
    gen_id: String,
    gen_hash: CryptoHash,
}

impl TxContext for ExplicitTxContext {
    fn round(&self) -> basics::Round {
        self.explicit_round
    }

    fn consensus_protocol(&self) -> config::ConsensusParams {
        self.proto.clone()
    }

    fn genesis_id(&self) -> String {
        self.gen_id.clone()
    }

    fn genesis_hash(&self) -> CryptoHash {
        self.gen_hash.clone()
    }
}
