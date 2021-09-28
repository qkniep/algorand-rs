// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::collections::HashMap;
use std::fmt;

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};

use crate::config;
use crate::data::basics::MicroAlgos;

/// Actions that may be performed when applying a delta to a TEAL key/value store.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeltaAction {
    /// Indicates that a TEAL byte slice should be stored at a key.
    SetBytes,

    /// Indicates that a TEAL uint should be stored at a key.
    SetUint,

    /// Indicates that the value for a particular key should be deleted.
    Delete,
}

/// Links a DeltaAction with a value to be set.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueDelta {
    pub action: DeltaAction,
    pub bytes: Vec<u8>,
    pub uint: u64,
}

impl ValueDelta {
    /// Converts a ValueDelta into a TealValue if possible, and returns None if the conversion is not possible.
    fn to_teal_value(&self) -> Option<TealValue> {
        match self.action {
            DeltaAction::SetBytes => Some(TealValue::new_bytes(self.bytes.clone())),
            DeltaAction::SetUint => Some(TealValue::new_uint(self.uint)),
            _ => None,
        }
    }
}

/// Map from key/value store keys to ValueDeltas, indicating what should happen for that key.
//msgp:allocbound StateDelta config.MaxStateDeltaKeys
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDelta(HashMap<String, ValueDelta>);

/*
/// Equal checks whether two StateDeltas are equal. We don't check for nilness
/// equality because an empty map will encode/decode as nil. So if our generated
/// map is empty but not nil, we want to equal a decoded nil off the wire.
fn (sd StateDelta) Equal(o StateDelta) bool {
    // Lengths should be the same
    if len(sd) != len(o) {
        return false
    }
    // All keys and deltas should be the same
    for k, v := range sd {
        // Other StateDelta must contain key
        ov, ok := o[k]
        if !ok {
            return false
        }

        // Other StateDelta must have same value for key
        if ov != v {
            return false
        }
    }
    return true
}
*/

impl StateDelta {
    /// Checks whether the keys and values in a StateDelta conform to the consensus parameters' maximum lengths.
    // TODO return Result<(), X> instead  of bool?
    pub fn is_valid(&self, proto: config::ConsensusParams) -> bool {
        if !self.0.is_empty() && proto.max_app_key_len == 0 {
            //return fmt.Errorf("delta not empty, but proto.MaxAppKeyLen is 0 (why did we make a delta?)")
            return false;
        }
        for (key, delta) in &self.0 {
            if key.len() > proto.max_app_key_len as usize {
                //return fmt.Errorf("key too long: length was %d, maximum is %d", len(key), proto.MaxAppKeyLen)
                return false;
            }
            match delta.action {
                DeltaAction::SetBytes => {
                    if delta.bytes.len() > proto.max_app_bytes_value_len as usize {
                        //return fmt.Errorf("value too long for key 0x%x: length was %d", key, len(delta.Bytes))
                        return false;
                    }
                    if key.len() + delta.bytes.len() > proto.max_app_sum_key_value_lens as usize {
                        //return fmt.Errorf("key/value total too long for key 0x%x: sum was %d", key, sum)
                        return false;
                    }
                }
                DeltaAction::SetUint => {}
                DeltaAction::Delete => {}
            }
        }
        true
    }
}

/// Sets maximums on the number of each type that may be stored.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateSchema {
    pub num_uint: u64,
    pub num_byte_slice: u64,
}

impl StateSchema {
    /// Adds two StateSchemas together.
    pub fn add_schema(&self, other: Self) -> Self {
        Self {
            num_uint: self.num_uint.saturating_add(other.num_uint),
            num_byte_slice: self.num_byte_slice.saturating_add(other.num_byte_slice),
        }
    }

    /// Subtracts one StateSchema from another.
    pub fn sub_schema(&self, other: StateSchema) -> StateSchema {
        Self {
            num_uint: self.num_uint.saturating_sub(other.num_uint),
            num_byte_slice: self.num_byte_slice.saturating_sub(other.num_byte_slice),
        }
    }

    /// Counts the total number of values that may be stored for particular schema.
    pub fn num_entries(&self) -> u64 {
        0_u64
            .saturating_add(self.num_uint)
            .saturating_add(self.num_byte_slice)
    }

    /// Computes the min balance requirements for a StateSchema based on the consensus parameters.
    pub fn min_balance(&self, proto: &config::ConsensusParams) -> MicroAlgos {
        // Flat cost for each key/value pair
        let flat_cost = proto
            .schema_min_balance_per_entry
            .saturating_mul(self.num_entries());

        // Cost for uints
        let uint_cost = proto.schema_uint_min_balance.saturating_mul(self.num_uint);

        // Cost for byte slices
        let bytes_cost = proto
            .schema_bytes_min_balance
            .saturating_mul(self.num_byte_slice);

        // Sum the separate costs
        let mut min = 0_u64;
        min = min.saturating_add(flat_cost);
        min = min.saturating_add(uint_cost);
        min = min.saturating_add(bytes_cost);

        MicroAlgos(min)
    }
}

/// Enum of the types in a TEAL program: Bytes and Uint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TealType {
    /// Represents the type of a byte slice in a TEAL program.
    Bytes,

    /// Represents the type of a uint in a TEAL program.
    Uint,
}

impl fmt::Display for TealType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TealType::Bytes => write!(f, "b"),
            TealType::Uint => write!(f, "u"),
        }
    }
}

/// Contains type information and a value, representing a value in a TEAL program.
// TODO make this an enum (or will that break codec compatibility with go-algorand?)
#[derive(Clone, Serialize, Deserialize)]
pub struct TealValue {
    pub teal_type: TealType,
    pub bytes: Vec<u8>,
    pub uint: u64,
}

impl TealValue {
    pub fn new_bytes(bytes: Vec<u8>) -> Self {
        Self {
            teal_type: TealType::Bytes,
            bytes,
            uint: 0,
        }
    }

    pub fn new_uint(uint: u64) -> Self {
        Self {
            teal_type: TealType::Uint,
            bytes: Vec::new(),
            uint,
        }
    }

    /// Creates ValueDelta from TealValue.
    pub fn to_value_delta(&self) -> ValueDelta {
        match self.teal_type {
            TealType::Uint => ValueDelta {
                action: DeltaAction::SetUint,
                bytes: Vec::new(),
                uint: self.uint,
            },
            TealType::Bytes => ValueDelta {
                action: DeltaAction::SetBytes,
                bytes: self.bytes.clone(),
                uint: 0,
            },
        }
    }
}

impl fmt::Display for TealValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.teal_type {
            TealType::Bytes => write!(f, "{}", HEXLOWER.encode(&self.bytes)),
            _ => write!(f, "{}", self.uint),
        }
    }
}

/// Represents a key/value store for use in an application's local or global state.
//msgp:allocbound TealKeyValue EncodedMaxKeyValueEntries
#[derive(Clone, Serialize, Deserialize)]
pub struct TealKeyValue(HashMap<String, TealValue>);

impl TealKeyValue {
    /// Calculates the number of each value type in a TealKeyValue and represents the result as a StateSchema.
    pub fn to_state_schema(&self) -> StateSchema {
        let mut schema = StateSchema::default();
        for value in self.0.values() {
            match value.teal_type {
                TealType::Bytes => schema.num_byte_slice += 1,
                TealType::Uint => schema.num_uint += 1,
            }
        }
        schema
    }
}
