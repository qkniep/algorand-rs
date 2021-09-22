// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::convert::TryFrom;
use std::fmt;

use super::*;
use crate::config;
use crate::data::basics;
use crate::protocol;
use crate::crypto::{self, hashable::*};

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
        let h = CryptoHash::try_from(s: &str)?;
        return Ok(TxID(h));
    }
}

/// Holds addresses with non-standard properties.
pub struct SpecialAddresses {
	pub fee_sink:    basics::Address,
	pub rewards_pool: basics::Address,
}

/// Captures the fields common to every transaction type.
pub struct Header {
	pub sender: basics::Address,
	pub fee: basics::MicroAlgos,
	pub first_valid: basics::Round,
	pub last_valid:  basics::Round,
	pub note:        Vec<u8>,
	pub genesis_id:  String,
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
pub struct Transaction {
	/// Type of transaction.
	pub tx_type: protocol::TxType,

	/// Common fields for all types of transactions
	pub header: Header,

	// Fields for different types of transactions
    // TODO use enum with one variant per TX type
	KeyregFields
	PaymentTxnFields
	AssetConfigTxnFields
	AssetTransferTxnFields
	AssetFreezeTxnFields
	ApplicationCallTxnFields
	CompactCertTxnFields
}

impl Hashable for Transaction {
    fn to_be_hashed(&self) -> (protocol::HashID, Vec<u8>) {
        (protocol::TRANSACTION, protocol::encode(self))
    }
}


/// Contains information about the transaction's execution.
#[derive(PartialEq, Eq)]
struct ApplyData {
	/// Closing amount for transaction.
	pub closing_amount: basics::MicroAlgos,

	/// Closing amount for asset transaction.
	pub asset_closing_amount: u64,

	// Rewards applied to the `sender`, `receiver`, and `close_remainder_to` accounts.
	pub sender_rewards:   basics::MicroAlgos,
	pub receiver_rewards: basics::MicroAlgos,
	pub close_rewards:   basics::MicroAlgos,
	pub eval_delta:      EvalDelta,

	// If asa or app is being created, the id used. Else 0.
	// Names chosen to match naming the corresponding txn.
	// These are populated on when MaxInnerTransactions > 0 (TEAL 5)
	pub config_asset:  basics::AssetIndex,
	pub application_id: basics::AppIndex,
}

/// Describes a group of transactions that must appear together in a specific order in a block.
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
    /// Returns the address that posted the transaction.
    /// This is the account that pays the associated fee.
    fn src(&self) -> basics::Address {
        self.sender
    }

    /// Returns the fee associated with this transaction.
    fn tx_fee(&self) -> basics::MicroAlgos {
        self.fee
    }

    /// Returns the note associated with this transaction.
    fn  note(&self) -> Vec<u8> {
        self.note
    }

    /// Returns the first round this transaction is valid.
    fn  first(&self) -> basics::Round {
        self.first_valid
    }

    /// Returns the first round this transaction is valid.
    fn last(&self) -> basics::Round {
        self.last_valid
    }

    /// Checks to see if the transaction is still alive (can be applied) at the specified Round.
    fn alive(&self, tc: &impl TxContext) -> Result<(), InvalidTx> {
        // Check round validity
        let round = tc.round();
        if round < self.first_valid || round > self.last_valid {
            return Err(InvalidTx::Dead {
                round,
                first_valid: self.first_valid,
                last_valid:  self.last_valid,
            });
        }

        // Check genesis ID
        let proto = tc.consensus_protocol();
        let genesis_id = tc.genesis_id();
        if self.genesis_id != "" && self.genesis_id != genesis_id {
            return Err(InvalidTx::GenesisIdMismatch(self.genesis_id, genesis_id));
        }

        // Check genesis hash
        if proto.support_genesis_hash {
            let genesis_hash = tc.genesis_hash();
            if !self.genesis_hash.is_zero() && self.genesis_hash != genesis_hash {
                return Err(InvalidTx::GenesisHashMismatch(self.genesis_hash, genesis_hash));
            }
            if proto.require_genesis_hash && self.genesis_hash.is_zero() {
                return Err(InvalidTx::GenesisHashMissing);
            }
        } else if !self.genesis_hash.is_zero() {
            return Err(InvalidTx::GenesisHashNotAllowed);
        }

        return Ok(());
    }
}

impl Transaction {
    /// Returns the TxID (i.e. cryptographic hash) of the transaction.
    fn id(&self) -> TxID {
        let enc = tx.MarshalMsg(append(protocol.GetEncodingBuf(), []byte(protocol.Transaction)...));
        defer protocol.PutEncodingBuf(enc)
        return TxID(crypto::hash(enc));
    }

    /// Signs this transaction using a given account's secrets.
    fn sign(&self, secrets: &crypto::SignatureSecrets) -> SignedTx {
        let sig = secrets.sign(self);
        let mut s = SignedTx{tx: self, sig};

        // Set the `auth_addr` if the signing key doesn't match the transaction sender.
        if basics::Address(secrets.SignatureVerifier) != self.header.sender {
            s.auth_addr = basics::Address::new(secrets.SignatureVerifier);
        }

        return s;
    }

    /// Checks if the transaction involves a given address.
    fn MatchAddress(&self, addr: basics::Address, spec: SpecialAddresses) -> bool {
        self.relevant_addrs(spec).contains(&addr)
    }

    /// Checks that the transaction looks reasonable on its own (but not necessarily valid against the actual ledger).
    /// It does not check signatures!
    fn is_well_formed(&self, spec: SpecialAddresses, proto: config::ConsensusParams) -> Result<(), MalformedTx> {
        match self.tx_type {
            protocol::PAYMENT_TX => {
                // In case that the fee sink is spending, check that this spend is to a valid address.
                self.check_spender(self.header, spec, proto)?;
            },
            protocol::KEY_REGISTRATION_TX => {
                if proto.EnableKeyregCoherencyCheck {
                    // ensure that the VoteLast is greater or equal to the VoteFirst
                    if self.KeyregTxnFields.vote_first > self.KeyregTxnFields.vote_last {
                        return Err(InvalidTx::KeyregFirstVotingRoundGreaterThanLastVotingRound);
                    }

                    // The trio of [VotePK, SelectionPK, VoteKeyDilution] needs to be all zeros or all non-zero for the transaction to be valid.
                    if !((self.KeyregTxnFields.VotePK == crypto.OneTimeSignatureVerifier{} && tx.KeyregTxnFields.SelectionPK == crypto.VRFVerifier{} && tx.KeyregTxnFields.VoteKeyDilution == 0) ||
                        (self.KeyregTxnFields.VotePK != crypto.OneTimeSignatureVerifier{} && tx.KeyregTxnFields.SelectionPK != crypto.VRFVerifier{} && tx.KeyregTxnFields.VoteKeyDilution != 0)) {
                        return Err(InvalidTx::KeyregNonCoherentVotingKeys);
                    }

                    // if it's a going offline transaction
                    if self.KeyregTxnFields.vote_key_dilution == 0 {
                        // check that we don't have any VoteFirst/VoteLast fields.
                        if tx.KeyregTxnFields.VoteFirst != 0 || tx.KeyregTxnFields.VoteLast != 0 {
                            return Err(KeyregOfflineTransactionHasVotingRounds);
                        }
                    } else {
                        // going online
                        if self.KeyregTxnFields.vote_last == 0 {
                            return Err(KeyregGoingOnlineWithZeroVoteLast);
                        }
                        if self.KeyregTxnFields.vote_first > self.header.last_valid+1 {
                            return Err(KeyregGoingOnlineWithFirstVoteAfterLastValid);
                        }
                    }
                }

                // Check that, if this tx is marking an account nonparticipating,
                // it supplies no key (as though it were trying to go offline).
                if self.KeyregTxnFields.nonparticipation {
                    if !proto.SupportBecomeNonParticipatingTransactions {
                        // if the transaction has the Nonparticipation flag high, but the protocol does not support
                        // that type of transaction, it is invalid.
                        return errKeyregTxnUnsupportedSwitchToNonParticipating
                    }
                    let supplies_null_neys = self.KeyregTxnFields.vote_pk == crypto.OneTimeSignatureVerifier{} || tx.KeyregTxnFields.SelectionPK == crypto.VRFVerifier{}
                    if !supplies_null_keys {
                        return errKeyregTxnGoingOnlineWithNonParticipating
                    }

                }
            },

        protocol::ASSET_CONFIG_TX =>
            if !proto.asset {
                return Err(InvalidTx::AssetTxsNotSupported);
            },

        protocol::ASSET_TRANSFER_TX =>
            if !proto.asset {
                return Err(InvalidTx::AssetTxsNotSupported);
            },

        protocol::ASSET_FREEZE_TX =>
            if !proto.asset {
                return Err(InvalidTx::AssetTxsNotSupported);
            },
        protocol::APP_CALL_TX =>
            if !proto.application {
                return Err(InvalidTx::AppTxsNotSupported);
            },

            // Ensure requested action is valid.
            match self.on_completion {
            case NoOpOC:
            case OptInOC:
            case CloseOutOC:
            case ClearStateOC:
            case UpdateApplicationOC:
            case DeleteApplicationOC:
            default:
                return fmt.Errorf("invalid application OnCompletion")
            }

            // Programs may only be set for creation or update.
            if self.application_id != 0 && self.on_completion != UpdateApplicationOC {
                if self.approval_program.len() != 0 || self.clear_state_program.len() != 0 {
                    return fmt.Errorf("programs may only be specified during application creation or update")
                }
            }

            let effective_epp := self.extra_program_pages;
            // Schemas and ExtraProgramPages may only be set during application creation.
            if self.application_id != 0 {
                if self.LocalStateSchema != (basics.StateSchema{}) ||
                    self.GlobalStateSchema != (basics.StateSchema{}) {
                    return fmt.Errorf("local and global state schemas are immutable")
                }
                if self.extra_program_pages != 0 {
                    return fmt.Errorf("tx.ExtraProgramPages is immutable")
                }

                if proto.EnableExtraPagesOnAppUpdate {
                    effectiveEPP = uint32(proto.MaxExtraAppProgramPages)
                }

            }

            // Limit total number of arguments
            if len(tx.ApplicationArgs) > proto.MaxAppArgs {
                return fmt.Errorf("too many application args, max %d", proto.MaxAppArgs)
            }

            // Sum up argument lengths
            let arg_sum = 0;
            for _, arg := range self.application_args {
                arg_sum = argSum.saturated_add(arg.len() as u64);
            }

            // Limit total length of all arguments
            if arg_sum > proto.max_app_total_arg_len as u64 {
                return fmt.Errorf("application args total length too long, max len %d bytes", proto.MaxAppTotalArgLen)
            }

            // Limit number of accounts referred to in a single ApplicationCall
            if len(tx.Accounts) > proto.MaxAppTxnAccounts {
                return fmt.Errorf("tx.Accounts too long, max number of accounts is %d", proto.MaxAppTxnAccounts)
            }

            // Limit number of other app global states referred to
            if len(tx.ForeignApps) > proto.MaxAppTxnForeignApps {
                return fmt.Errorf("tx.ForeignApps too long, max number of foreign apps is %d", proto.MaxAppTxnForeignApps)
            }

            if len(tx.ForeignAssets) > proto.MaxAppTxnForeignAssets {
                return fmt.Errorf("tx.ForeignAssets too long, max number of foreign assets is %d", proto.MaxAppTxnForeignAssets)
            }

            // Limit the sum of all types of references that bring in account records
            if len(tx.Accounts)+len(tx.ForeignApps)+len(tx.ForeignAssets) > proto.MaxAppTotalTxnReferences {
                return fmt.Errorf("tx has too many references, max is %d", proto.MaxAppTotalTxnReferences)
            }

            if tx.ExtraProgramPages > uint32(proto.MaxExtraAppProgramPages) {
                return fmt.Errorf("tx.ExtraProgramPages too large, max number of extra pages is %d", proto.MaxExtraAppProgramPages)
            }

            lap := len(tx.ApprovalProgram)
            lcs := len(tx.ClearStateProgram)
            pages := int(1 + effectiveEPP)
            if lap > pages*proto.MaxAppProgramLen {
                return fmt.Errorf("approval program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
            } else if lcs > pages*proto.MaxAppProgramLen {
                return fmt.Errorf("clear state program too long. max len %d bytes", pages*proto.MaxAppProgramLen)
            } else if lap+lcs > pages*proto.MaxAppTotalProgramLen {
                return fmt.Errorf("app programs too long. max total len %d bytes", pages*proto.MaxAppTotalProgramLen)
            } else if tx.LocalStateSchema.NumEntries() > proto.MaxLocalSchemaEntries {
                return fmt.Errorf("tx.LocalStateSchema too large, max number of keys is %d", proto.MaxLocalSchemaEntries)
            } else if tx.GlobalStateSchema.NumEntries() > proto.MaxGlobalSchemaEntries {
                return fmt.Errorf("tx.GlobalStateSchema too large, max number of keys is %d", proto.MaxGlobalSchemaEntries)
            }

        case protocol.CompactCertTx:
            if proto.CompactCertRounds == 0 {
                return fmt.Errorf("compact certs not supported")
            }

            // This is a placeholder transaction used to store compact certs
            // on the ledger, and ensure they are broadly available.  Most of
            // the fields must be empty.  It must be issued from a special
            // sender address.
            if self.sender != CompactCertSender {
                return fmt.Errorf("sender must be the compact-cert sender")
            } else if !self.fee.is_zero() {
                return fmt.Errorf("fee must be zero")
            } else if self.note.len() != 0 {
                return fmt.Errorf("note must be empty")
            } else if !self.group.is_zero() {
                return fmt.Errorf("group must be zero")
            } else if !self.rekey_to.is_zero() {
                return fmt.Errorf("rekey must be zero")
            } else if self.lease != [32]byte{} {
                return fmt.Errorf("lease must be zero")
            }

        default:
            // TODO can't happen with Rust enums
            // TODO add an extra Unknown value to enum (and use in codec)
            return fmt.Errorf("unknown tx type %v", self.tx_type)
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

        if !proto.enable_fee_pooling && self.header.fee <= basics::MicroAlgos(proto.min_tx_fee) {
            if self.tx_type == protocol.compact_cert_tx {
                // Zero fee allowed for compact cert txn.
            } else {
                return Err(InvalidTx::FeeLessThanMin(self.fee)); // , proto.min_tx_fee));
            }
        }
        if self.header.last_valid < self.header.first_valid {
            Err(InvalidTx::BadValidityRange(self.header.first_valid, self.header.last_valid))
        } else if self.header.last_valid.0-self.header.first_valid.0 > proto.max_txn_life {
            Err(InvalidTx::ExcessiveValidityRange(self.header.first_valid, self.header.last_valid))
        } else if self.header.note.len() > proto.max_tx_note_bytes {
            Err(InvalidTx::NoteTooBig(self.header.note.len(), proto.max_tx_note_bytes))
        } else if self.AssetConfigTxnFields.asset_params.asset_name.len() > proto.MaxAssetNameBytes {
            Err(InvalidTx::AssetNameTooBig(self.AssetConfigTxnFields.asset_params.asset_name.len(), proto.max_asset_name_bytes))
        } else if self.AssetConfigTxnFields.asset_params.unit_name.len() > proto.MaxAssetUnitNameBytes {
            Err(InvalidTx::AssetUnitNameTooBig(self.AssetConfigTxnFields.asset_params.unit_name.len(), proto.max_asset_unit_name_bytes))
        } else if self.AssetConfigTxnFields.asset_params.url.len() > proto.MaxAssetURLBytes {
            Err(InvalidTx::AssetUrlTooBig(self.AssetConfigTxnFields.asset_params.url.len(), proto.max_asset_url_bytes))
        } else if self.AssetConfigTxnFields.asset_params.decimals > proto.MaxAssetDecimals {
            Err(InvalidTx::AssetDecimalsTooHigh(self.AssetConfigTxnFields.asset_params.decimals, proto.max_asset_decimals))
        } else if self.header.sender == spec.rewards_pool {
            // this check is just to be safe, but reaching here seems impossible, since it requires computing a preimage of rwpool
            unreachable!("transaction from incentive pool");
        } else if self.header.sender.is_zero() {
            Err(InvalidTx::ZeroSender)
        } else if !proto.support_transaction_leases && (self.header.lease != [0; 32]) {
            Err(InvalidTx::LeasesNotSupported)
        } else if !proto.support_tx_groups && (!self.group.is_zero()) {
            Err(InvalidTx::GroupsNotSupported)
        } else if !proto.support_rekeying && (!self.rekey_to.is_zero()) {
            Err(InvalidTx::RekeyingNotSupported)
        } else {
            Ok(());
        }
    }

    /// Returns the addresses whose balance records this transaction will need to access.
    /// The header's default is to return just the sender and the fee sink.
    fn relevant_addrs(&self, spec: SpecialAddresses) -> Vec<basics::Address> {
        let addrs = vec![self.header.sender, spec.fee_sink];

        match self.tx_type {
            protocol::PAYMENT_TX => {
                addrs.push(self.PaymentTxnFields.receiver);
                if !self.PaymentTxnFields.CloseRemainderTo.is_zero() {
                    addrs.push(self.PaymentTxnFields.CloseRemainderTo);
                }
            },
            protocol::ASSET_TRANSFER_TX => {
                addrs.push(self.AssetTransferTxnFields.asset_receiver);
                if !self.AssetTransferTxnFields.asset_close_to.is_zero() {
                    addrs.push(self.AssetTransferTxnFields.asset_close_to);
                }
                if !self.AssetTransferTxnFields.asset_sender.is_zero() {
                    addrs.push(self.AssetTransferTxnFields.asset_sender);
                }
            },
            _ => {},
        };

        return addrs
    }

    /// Returns the amount paid to the recipient in this payment.
    fn tx_amount(&self) -> basics::MicroAlgos {
        match self.tx_type {
            protocol::PAYMENT_TX => self.PaymentTxnFields.amount,
            _ => basics::MicroAlgos(0),
        }
    }

    /// Returns the address of the receiver. If the transaction has no receiver, it returns the empty address.
    fn get_receiver_rddress(&self) -> Option<basics::Address> {
        match self.tx_type {
            protocol::PAYMENT_TX => Ok(self.PaymentTxnFields.receiver),
            protocol::ASSET_TRANSFER_TX => Ok(self.AssetTransferTxnFields.asset_receiver),
            _ => None,
        }
    }

    /// Returns the estimated encoded size of the transaction including the signature.
    /// This function is to be used for calculating the fee.
    /// Note that it may be an underestimate if the transaction is signed in an unusual way
    /// (e.g., with an authaddr or via multisig or logicsig).
    fn estimate_encoded_size(&self) -> i32 {
        // Make a signed transaction with a nonzero signature and encode it.
        let stx = SignedTx {
            tx,
            sig: crypto::Signature{1},
        };
        return stx.get_encoded_length();
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
	proto:         config::ConsensusParams,
	gen_id:         String,
	gen_hash:      CryptoHash,
}

impl TxContext for ExplicitTxContext {
    fn round(&self) -> basics::Round {
        self.explicit_round
    }

    fn consensus_protocol(&self) -> config::ConsensusParams {
        self.proto
    }

    fn genesis_id(&self) -> String {
        self.gen_id
    }

    fn genesis_hash(&self) -> CryptoHash {
        self.gen_hash
    }
}

#[cfg(test)]
mod tests {
	use super::*;

    use rand::{RngCore, thread_rng};

	#[test]
    fn estimate_encoded_size() {
        let addr = basics::Address::from_str("NDQCJNNY5WWWFLP4GFZ7MEF2QJSMZYK6OWIV2AQ7OMAVLEFCGGRHFPKJJA").unwrap();

        let mut rng = thread_rng();
        let mut buf = [0; 10];
        rng.fill_bytes(&mut buf);

        let proto = config::Consensus[protocol::ConsensusCurrentVersion];
        let tx = Transaction {
            tx_type: protocol::PAYMENT_TX,
            header: Header {
                sender:     addr,
                fee:        basics::MicroAlgos(100),
                first_valid: basics::Round(1000),
                last_valid:  basics::Round(1000 + proto.MaxTxnLife),
                note:       buf.to_vec(),
            },
            additional_fields: AdditionalTxFields::Payment {
                receiver: addr,
                amount:   basics::MicroAlgos(100),
            },
        }

        assert_eq!(tx.estimate_encoded_size(), 200);
    }

    /*
    fn generate_dummy_go_nonparticpating_tx(addr basics.Address) (tx Transaction) {
        buf := make([]byte, 10)
        crypto.RandBytes(buf[:])

        proto := config.Consensus[protocol.ConsensusCurrentVersion]
        tx = Transaction{
            Type: protocol.KeyRegistrationTx,
            Header: Header{
                Sender:     addr,
                Fee:        basics.MicroAlgos{Raw: proto.MinTxnFee},
                FirstValid: 1,
                LastValid:  300,
            },
            KeyregTxnFields: KeyregTxnFields{
                Nonparticipation: true,
                VoteFirst:        0,
                VoteLast:         0,
            },
        }

        tx.KeyregTxnFields.Nonparticipation = true
        return tx
    }
    */
}
