// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use crate::data::basics;

/// Allocation bound for the maximum number of ApplicationArgs that a transaction decoded off of the wire can contain.
/// Its value is verified against consensus parameters in TestEncodedAppTxnAllocationBounds.
const ENCODED_MAX_APPLICATION_ARGS: u32 = 32;

/// Allocation bound for the maximum number of Accounts that a transaction decoded off of the wire can contain.
/// Its value is verified against consensus parameters in TestEncodedAppTxnAllocationBounds
const ENCODED_MAX_ACCOUNTS: u32 = 32;

/// Allocation bound for the maximum number of ForeignApps that a transaction decoded off of the wire can contain.
/// Its value is verified against consensus parameters in TestEncodedAppTxnAllocationBounds
const ENCODED_MAX_FOREIGN_APPS: u32 = 32;

/// Allocation bound for the maximum number of ForeignAssets that a transaction decoded off of the wire can contain.
/// Its value is verified against consensus parameters in TestEncodedAppTxnAllocationBounds
const ENCODED_MAX_FOREIGN_ASSETS: u32 = 32;

/// Captures the transaction fields used for all interactions with applications.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppCallFields {
    /// Is 0 when creating an application, and nonzero when calling an existing application.
    pub application_id: basics::AppIndex,

    /// Specifies an optional side-effect that this transaction will have on the balance record of the sender
    /// or the application's creator.
    /// See the documentation for the OnCompletion type for more information on each possible value.
    pub on_completion: OnCompletion,

    /// Arguments accessible to the executing ApprovalProgram or ClearStateProgram.
    pub application_args: Vec<Vec<u8>>,

    /// Accounts are accounts whose balance records are accessible
    /// by the executing ApprovalProgram or ClearStateProgram. To
    /// access LocalState or an ASA balance for an account besides
    /// the sender, that account's address must be listed here (and
    /// since v4, the ForeignApp or ForeignAsset must also include
    /// the app or asset id).
    pub accounts: Vec<basics::Address>,

    /// ForeignApps are application IDs for applications besides
    /// this one whose GlobalState (or Local, since v4) may be read
    /// by the executing ApprovalProgram or ClearStateProgram.
    pub foreign_apps: Vec<basics::AppIndex>,

    /// Asset IDs for assets whose AssetParams (and since v4, Holdings) may be read by the executing
    /// ApprovalProgram or ClearStateProgram.
    pub foreign_assets: Vec<basics::AssetIndex>,

    /// LocalStateSchema specifies the maximum number of each type that may
    /// appear in the local key/value store of users who opt in to this
    /// application. This field is only used during application creation
    /// (when the ApplicationID field is 0),
    pub local_state_schema: basics::StateSchema,

    /// GlobalStateSchema specifies the maximum number of each type that may
    /// appear in the global key/value store associated with this
    /// application. This field is only used during application creation
    /// (when the ApplicationID field is 0).
    pub global_state_schema: basics::StateSchema,

    /// The stateful TEAL bytecode that executes on all ApplicationCall transactions associated with this application,
    /// except for those where OnCompletion is equal to ClearStateOC.
    /// If this program fails, the transaction is rejected.
    /// This program may read and write local and global state for this application.
    pub approval_program: Vec<u8>,

    /// Stateful TEAL bytecode that executes on ApplicationCall transactions associated with this application when
    /// OnCompletion is equal to ClearStateOC.
    /// This program will not cause the transaction to be rejected, even if it fails.
    /// This program may read and write local and global state for this application.
    pub clear_state_program: Vec<u8>,

    /// Specifies the additional app program len requested in pages.
    /// A page is MaxAppProgramLen bytes.
    /// This field enables execution of app programs larger than the default config, MaxAppProgramLen.
    pub extra_program_pages: u32,
    // If you add any fields here, remember you MUST modify the Empty
    // method below!
}

/// Enum representing some layer 1 side effect that an
/// ApplicationCall transaction will have if it is included in a block.
//go:generate stringer -type=OnCompletion -output=application_string.go
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OnCompletion {
    /// NoOpOC indicates that an application transaction will simply call its ApprovalProgram.
    NoOpOC,

    /// OptInOC indicates that an application transaction will allocate some
    /// LocalState for the application in the sender's account
    OptInOC,

    /// CloseOutOC indicates that an application transaction will deallocate
    /// some LocalState for the application from the user's account
    CloseOutOC,

    /// ClearStateOC is similar to CloseOutOC, but may never fail.
    /// This allows users to reclaim their minimum balance from an application they no longer wish to opt in to.
    /// When an ApplicationCall transaction's OnCompletion is ClearStateOC, the ClearStateProgram
    /// executes instead of the ApprovalProgram.
    ClearStateOC,

    /// Indicates that an application transaction will
    /// update the ApprovalProgram and ClearStateProgram for the application.
    UpdateApplicationOC,

    /// DeleteApplicationOC indicates that an application transaction will
    /// delete the AppParams for the application from the creator's balance record
    DeleteApplicationOC,
}

impl Default for OnCompletion {
    fn default() -> Self {
        OnCompletion::NoOpOC
    }
}

impl AppCallFields {
    /*
    /// Indicates whether or not all the fields in the ApplicationCallTxnFields are zeroed out.
    fn empty(&self) -> bool {
        if self.application_id != 0 {
            return false
        }
        if self.on_completion != 0 {
            return false
        }
        if self.application_args != nil {
            return false
        }
        if self.accounts != nil {
            return false
        }
        if self._foreign_apps != nil {
            return false
        }
        if self.foreign_assets != nil {
            return false
        }
        if self.local_state_schema != (basics::StateSchema{}) {
            return false
        }
        if self.global_state_schema != (basics::StateSchema{}) {
            return false
        }
        if self.approval_program != nil {
            return false
        }
        if self.clear_state_program != nil {
            return false
        }
        if self.extra_program_pages != 0 {
            return false
        }
        return true
    }
    */

    /// Converts an integer index into an address associated with the transaction.
    /// Index 0 corresponds to the transaction sender, and an index > 0 corresponds to an offset into txn.Accounts.
    /// Returns an error if the index is not valid.
    fn address_by_index(
        &self,
        account_idx: u64,
        sender: basics::Address,
    ) -> Result<basics::Address, ()> {
        // Index 0 always corresponds to the sender
        if account_idx == 0 {
            return Ok(sender);
        }

        // An index > 0 corresponds to an offset into txn.accounts. Check to
        // make sure the index is valid.
        if account_idx > self.accounts.len() as u64 {
            //err := fmt.Errorf("invalid Account reference %d", accountIdx)
            return Err(());
        }

        // accountIdx must be in [1, len(self.accounts)]
        return Ok(self.accounts[account_idx as usize - 1].clone());
    }

    /// Converts an address into an integer offset into [txn.Sender, txn.Accounts[0], ...],
    /// returning the index at the first match.
    /// It returns an error if there is no such match.
    pub fn index_by_address(
        &self,
        target: basics::Address,
        sender: basics::Address,
    ) -> Result<u64, ()> {
        // Index 0 always corresponds to the sender
        if target == sender {
            return Ok(0);
        }

        // Otherwise we index into self.accounts
        if let Some(index) = self.accounts.iter().position(|a| *a == target) {
            return Ok(index as u64 + 1);
        }

        //return Err(fmt.Errorf("invalid Account reference %s", target))
        return Err(());
    }

    /// Converts an integer index into an application id associated with the transaction.
    /// Index 0 corresponds to the current app, and an index > 0 corresponds to an offset into txn.ForeignApps.
    /// Returns an error if the index is not valid.
    pub fn app_id_by_index(&self, i: u64) -> Result<basics::AppIndex, ()> {
        // Index 0 always corresponds to the current app
        if i == 0 {
            return Ok(self.application_id);
        }

        // An index > 0 corresponds to an offset into txn.ForeignApps. Check to
        // make sure the index is valid.
        if i > self.foreign_apps.len() as u64 {
            //err := fmt.Errorf("invalid Foreign App reference %d", i)
            return Err(());
        }

        // aidx must be in [1, len(self.foreign_apps)]
        return Ok(self.foreign_apps[i as usize - 1]);
    }

    /// Converts an application id into an integer offset into [current app, txn.ForeignApps[0], ...],
    /// returning the index at the first match.
    /// It returns an error if there is no such match.
    pub fn index_by_app_id(&self, app_id: basics::AppIndex) -> Result<u64, ()> {
        // Index 0 always corresponds to the current app
        if app_id == self.application_id {
            return Ok(0);
        }
        // Otherwise we index into self.foreign_apps
        if let Some(index) = self.foreign_apps.iter().position(|&id| id == app_id) {
            return Ok(index as u64 + 1);
        }

        //return 0, fmt.Errorf("invalid Foreign App reference %d", appID)
        return Err(());
    }
}
