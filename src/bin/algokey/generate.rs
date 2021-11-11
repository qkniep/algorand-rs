// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use clap::{AppSettings, Parser};
use ed25519_dalek::{PublicKey, SecretKey, SECRET_KEY_LENGTH};
use rand::{thread_rng, RngCore};

use algorsand::crypto::mnemonic;
use algorsand::data::basics::address::Address;

#[derive(Parser)]
#[clap(setting = AppSettings::ArgRequiredElseHelp)]
pub struct GenerateCmd {
    /// Private key filename
    #[clap(short = 'f', long = "keyfile")]
    sk_file: String,
    /// Public key filename
    #[clap(short = 'p', long = "pubkeyfile")]
    pk_file: String,
}

impl GenerateCmd {
    pub fn entrypoint(&self) {
        let mut rng = thread_rng();
        let mut seed = [0; SECRET_KEY_LENGTH];
        rng.fill_bytes(&mut seed);

        let words = mnemonic::key_to_mnemonic(seed);

        let key = SecretKey::from_bytes(&seed).unwrap();
        let pk: PublicKey = (&key).into();
        let pk_chk = Address(*pk.as_bytes()).to_string();

        println!("Private key mnemonic: {}", words.join(" "));
        println!("Public key: {}", pk_chk);

        if !self.sk_file.is_empty() {
            if let Err(e) = write_sk(&self.sk_file, &seed) {
                println!("[Error] Could not write private key to file: {}", e);
            }
        }

        if !self.pk_file.is_empty() {
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
    f.write_all(data)
}

fn write_pk(filename: &impl AsRef<Path>, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .read(false)
        .create(true)
        .truncate(true)
        .mode(0o666)
        .open(filename)?;
    f.write_all(data)
}
