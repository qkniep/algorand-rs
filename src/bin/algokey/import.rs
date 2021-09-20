// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use clap::{AppSettings, Clap};
use ed25519_dalek::{PublicKey, SecretKey};

use algorsand::crypto::mnemonic;
use algorsand::data::basics::address::Address;

/// Import key files from mnemonic
#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
pub struct ImportCmd {
    /// Private mnemonic phrase to import
    #[clap(short = 'm', long = "mnemonic", required = true)]
    mnemonic: String,
    /// Private key filename to write to
    #[clap(short = 'f', long = "keyfile", required = true)]
    sk_file: String,
    /// Public key filename to write to
    #[clap(short = 'p', long = "pubkeyfile", required = false)]
    pk_file: String,
}

impl ImportCmd {
    pub fn entrypoint(&self) {
        let seed = mnemonic::phrase_to_key(&self.mnemonic);
        if let Err(e) = seed.as_ref() {
            println!("[Error] Invalid mnemonic provided: {}", e);
        }

        let key = SecretKey::from_bytes(seed.as_ref().unwrap()).unwrap();
        let pk: PublicKey = (&key).into();
        let pk_chk = Address(*pk.as_bytes()).to_string();

        println!("Private key mnemonic: {}", self.mnemonic);
        println!("Public key: {}", pk_chk);

        if self.sk_file != "" {
            if let Err(e) = write_sk(&self.sk_file, seed.as_ref().unwrap()) {
                println!("[Error] Could not write private key to file: {}", e);
            }
        }

        if self.pk_file != "" {
            if let Err(e) = write_pk(&self.pk_file, pk_chk.as_bytes()) {
                println!("[Error] Could not write public key to file: {}", e);
            }
        }
    }
}

fn write_sk(filename: &impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .read(false)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(filename)?;
    f.write(data)?;
    return Ok(());
}

fn write_pk(filename: &impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .read(false)
        .create(true)
        .truncate(true)
        .mode(0o666)
        .open(filename)?;
    f.write(data)?;
    return Ok(());
}
