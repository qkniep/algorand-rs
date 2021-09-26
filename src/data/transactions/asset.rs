// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use serde::{Deserialize, Serialize};

use crate::data::basics;

/// Fields used for asset allocation, re-configuration, and destruction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetConfigFields {
    /// ConfigAsset is the asset being configured or destroyed.
    /// A zero value means allocation.
    pub config_asset: basics::AssetIndex,

    /// Parameters for the asset being created or re-configured.
    /// A zero value means destruction.
    pub asset_params: basics::AssetParams,
}

/// Fields used for asset transfers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetTransferFields {
    pub transfer_asset: basics::AssetIndex,

    /// The amount of asset to transfer.
    /// A zero amount transferred to self allocates that asset in the account's Assets map.
    pub asset_amount: u64,

    /// Sender of the transfer.
    /// If this is not a zero value, the real transaction sender must be the Clawback address from the AssetParams.
    /// If this is the zero value, the asset is sent from the transaction's Sender.
    pub asset_sender: basics::Address,

    /// Recipient of the transfer.
    pub asset_receiver: basics::Address,

    /// Indicates that the asset should be removed from the account's Assets map,
    /// and specifies where the remaining asset holdings should be transferred.
    /// It's always valid to transfer remaining asset holdings to the creator account.
    pub asset_close_to: basics::Address,
}

/// Fields used for freezing asset slots.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetFreezeFields {
    /// Address of the account whose asset slot is being frozen or un-frozen.
    pub freeze_account: basics::Address,

    /// Asset ID being frozen or un-frozen.
    pub freeze_asset: basics::AssetIndex,

    /// The new frozen value.
    pub asset_frozen: bool,
}
