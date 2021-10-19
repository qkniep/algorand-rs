// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::str::FromStr;

use clap::{AppSettings, Parser};
use data_encoding::BASE64;

use algorsand::data::{
    account,
    basics::{units::Round, Address},
};

/// Manage participation keys
#[derive(Parser)]
#[clap(setting = AppSettings::ArgRequiredElseHelp)]
pub struct PartCmd {
    #[clap(subcommand)]
    subcmd: PartSubCmd,
}

#[derive(Parser)]
pub enum PartSubCmd {
    Generate(PartGenerateCmd),
    Info(PartInfoCmd),
    Reparent(PartReparentCmd),
}

/// Generate new participation key
#[derive(Parser)]
pub struct PartGenerateCmd {
    /// Participation key filename
    #[clap(short, long, required = true)]
    keyfile: String,
    /// First round of validity for participation key
    #[clap(short, long, required = true)]
    first: u64,
    /// Last round of validity for participation key
    #[clap(short, long, required = true)]
    last: u64,
    /// Key dilution (default: sqrt(last-first))
    #[clap(short, long)]
    dilution: u64,
    /// Address of parent account
    #[clap(short, long)]
    parent: String,
}

/// Print participation key information
#[derive(Parser)]
pub struct PartInfoCmd {
    /// Participation key filename
    #[clap(short, long, required = true)]
    keyfile: String,
}

/// Change parent address of participation key
#[derive(Parser)]
pub struct PartReparentCmd {
    /// Participation key filename
    #[clap(short, long, required = true)]
    keyfile: String,
    /// Address to be set as new parent account
    #[clap(short, long, required = true)]
    parent: String,
}

impl PartCmd {
    pub fn entrypoint(&self) {
        match &self.subcmd {
            PartSubCmd::Generate(g) => g.entrypoint(),
            PartSubCmd::Info(i) => i.entrypoint(),
            PartSubCmd::Reparent(r) => r.entrypoint(),
        }
    }
}

impl PartGenerateCmd {
    pub fn entrypoint(&self) {
        let key_dilution = match self.dilution {
            0 => 1 + ((self.last - self.first) as f64).sqrt() as u64,
            _ => self.dilution,
        };

        let res = account::Participation::fill_db_with_participation_keys(
            Address::from_str(&self.parent).unwrap(),
            Round(self.first),
            Round(self.last),
            key_dilution,
        );

        match res {
            Ok(part_key) => print_participation_key(part_key),
            Err(e) => {
                eprintln!("Failed to create participation key: {}", e);
                std::process::exit(1);
            }
        }
    }
}

impl PartInfoCmd {
    pub fn entrypoint(&self) {
        let res = account::Participation::restore();

        match res {
            Ok(part_key) => print_participation_key(part_key),
            Err(e) => {
                eprintln!("Failed to load participation key: {}", e);
                std::process::exit(1);
            }
        }
    }
}

impl PartReparentCmd {
    pub fn entrypoint(&self) {
        let parent = Address::from_str(&self.parent).unwrap_or_else(|e| {
            eprintln!("Failed to parse parent address: {}", e);
            std::process::exit(1);
        });

        let mut part_key = account::Participation::restore().unwrap_or_else(|e| {
            eprintln!("Failed to load participiation key: {}", e);
            std::process::exit(1);
        });

        part_key.parent = parent;

        match part_key.persist_new_parent() {
            Ok(_) => print_participation_key(part_key),
            Err(e) => {
                eprintln!("Failed to store participation key: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn print_participation_key(part_key: account::Participation) {
    let voting_pk = BASE64.encode(part_key.voting.verifier.as_bytes());
    println!("Parent address: {}", part_key.parent);
    println!("VRF public key: {}", part_key.vrf.public());
    println!("Voting pub key: {}", voting_pk);
    println!("First valid:    {}", part_key.first_valid);
    println!("Last valid:     {}", part_key.last_valid);
    println!("Key dilution:   {}", part_key.key_dilution);
    println!("First batch:    {}", part_key.voting.first_batch);
    println!("First offset:   {}", part_key.voting.first_offset);
}
