// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use clap::Parser;
use ed25519_dalek::{PublicKey, SecretKey, SECRET_KEY_LENGTH};

use algorsand::crypto::mnemonic;
use algorsand::data::basics::address::Address;

/// Export key file to mnemonic and public key.
#[derive(Parser)]
pub struct ExportCmd {
    /// Private key filename
    #[clap(short = 'f', long = "keyfile", required = true)]
    sk_file: String,
    /// Public key filename
    #[clap(short = 'p', long = "pubkeyfile", required = false)]
    pk_file: String,
}

impl ExportCmd {
    pub fn entrypoint(&self) {
        let seed = load_sk(&self.sk_file).unwrap();
        let words = mnemonic::key_to_mnemonic(seed);

        let key = SecretKey::from_bytes(&seed).unwrap();
        let pk: PublicKey = (&key).into();
        let pk_chk = Address(*pk.as_bytes()).to_string();

        println!("Private key mnemonic: {}", words.join(" "));
        println!("Public key: {}", pk_chk);

        if self.pk_file != "" {
            if let Err(e) = write_pk(&self.pk_file, pk_chk.as_bytes()) {
                println!("[Error] Could not write public key to file: {}", e);
            }
        }
    }
}

fn load_sk(filename: &impl AsRef<Path>) -> io::Result<[u8; SECRET_KEY_LENGTH]> {
    let mut buf = [0; SECRET_KEY_LENGTH];
    let mut f = fs::File::open(filename)?;
    f.read_exact(&mut buf)?;
    return Ok(buf);
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
