// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod consensus;
mod hash;
mod tags;
mod txtype;

pub use consensus::*;
pub use hash::*;
pub use tags::*;
pub use txtype::*;

pub type NetworkID = &'static str;
