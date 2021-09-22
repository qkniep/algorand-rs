// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

pub type TxType = &'static str;

/// Indicates a payment transaction.
pub const PAYMENT_TX: TxType = "pay";

/// Indicates a transaction that registers participation keys.
pub const KEY_REGISTRATION_TX: TxType = "keyreg";

/// Creates, re-configures, or destroys an asset.
pub const ASSET_CONFIG_TX: TxType = "acfg";

/// Transfers assets between accounts (optionally closing).
pub const ASSET_TRANSFER_TX: TxType = "axfer";

/// Changes the freeze status of an asset.
pub const ASSET_FREEZE_TX: TxType = "afrz";

/// Allows creating, deleting, and interacting with an application.
pub const APP_CALL_TX: TxType = "appl";

/// Records a compact certificate.
pub const COMPACT_CERT_TX: TxType = "cert";

/// Signals an error.
pub const UNKNOWN_TX: TxType = "unknown";
