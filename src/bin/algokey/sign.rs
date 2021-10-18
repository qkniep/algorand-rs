// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use clap::{AppSettings, Parser};
use ed25519_dalek::{Keypair, SECRET_KEY_LENGTH};

use algorsand::crypto::mnemonic;
use algorsand::data::{basics, transactions::*};

#[derive(Parser)]
#[clap(setting = AppSettings::ArgRequiredElseHelp)]
pub struct SignCmd {
    /// Private key filename
    #[clap(short = 'f', long = "keyfile")]
    sk_file: String,
    /// Private mnemonic phrase
    #[clap(short = 'm', long = "mnemonic")]
    mnemonic: String,
    /// Transaction input filename
    #[clap(short = 't', long = "txfile", required = true)]
    tx_file: String,
    /// Signed transaction output filename
    #[clap(short = 'o', long = "outfile", required = true)]
    out_file: String,
}

impl SignCmd {
    pub fn entrypoint(&self) {
        let seed = load_keyfile_or_mnemonic(&self.sk_file, &self.mnemonic);
        let kp = Keypair::from_bytes(&seed).unwrap();

        // load tx from file
        let in_f = fs::File::open(&self.tx_file).unwrap();
        let tx: Transaction = rmp_serde::decode::from_read(in_f).unwrap();

        // sign tx
        let mut sig_tx = tx.sign(&kp);
        if sig_tx.tx.header().sender != basics::Address(kp.public.to_bytes()) {
            sig_tx.auth_addr = basics::Address(kp.public.to_bytes());
        }

        // write signed tx back to file
        let mut out_f = fs::File::open(&self.out_file).unwrap();
        rmp_serde::encode::write(&mut out_f, &sig_tx);
    }
}

fn load_keyfile_or_mnemonic(keyfile: &str, mnemonic: &str) -> [u8; SECRET_KEY_LENGTH] {
    if keyfile != "" && mnemonic != "" {
        eprintln!("Must specify one of keyfile or mnemonic");
        std::process::exit(1);
    }

    if keyfile != "" {
        return load_sk(&keyfile).unwrap();
    } else if mnemonic != "" {
        return mnemonic::phrase_to_key(mnemonic).unwrap();
    }

    eprintln!("Must specify one of keyfile or mnemonic");
    std::process::exit(1);
}

fn load_sk(filename: &impl AsRef<Path>) -> io::Result<[u8; SECRET_KEY_LENGTH]> {
    let mut buf = [0; SECRET_KEY_LENGTH];
    let mut f = fs::File::open(filename)?;
    f.read_exact(&mut buf)?;
    return Ok(buf);
}
