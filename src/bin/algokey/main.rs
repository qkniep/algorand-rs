// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

mod export;
mod generate;
mod import;
//mod multisig;
//mod part;
mod sign;

use clap::{AppSettings, Clap};

use export::ExportCmd;
use generate::GenerateCmd;
use import::ImportCmd;
//use multisig::MultisigCmd;
//use part::PartCmd;
use sign::SignCmd;

/// CLI for managing Algorand keys
#[derive(Clap)]
#[clap(name = "algokey", version = "0.1")]
#[clap(author = "Quentin M. Kniep <hello@quentinkniep.com>")]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::ArgRequiredElseHelp)]
struct RootCmd {
    // Sets a custom config file. Could have been an Option<T> with no default too
    //#[clap(short, long, default_value = "default.conf")]
    //config: String,
    #[clap(subcommand)]
    subcmd: SubCmd,
}

#[derive(Clap)]
enum SubCmd {
    Generate(GenerateCmd),
    Import(ImportCmd),
    Export(ExportCmd),
    Sign(SignCmd),
    //Multisig(MultisigCmd),
    //Part(PartCmd),
}

fn main() {
    let cmd: RootCmd = RootCmd::parse();

    /*// Hidden command to generate docs in a given directory algokey generate-docs [path]
    if len(os.Args) == 3 && os.Args[1] == "generate-docs" {
        err := doc.GenMarkdownTree(rootCmd, os.Args[2])
        if err != nil {
            fmt.Println(err)
            os.Exit(1)
        }
        os.Exit(0)
    }*/

    /*match opts.verbose {
        0 => println!("No verbose info"),
        1 => println!("Some verbose info"),
        2 => println!("Tons of verbose info"),
        _ => println!("Don't be ridiculous"),
    }*/

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match cmd.subcmd {
        SubCmd::Generate(c) => c.entrypoint(),
        SubCmd::Import(i) => i.entrypoint(),
        SubCmd::Export(e) => e.entrypoint(),
        SubCmd::Sign(s) => s.entrypoint(),
        //SubCmd::Multisig(m) => m.entrypoint(),
        //SubCmd::Part(p) => p.entrypoint(),
    };
}
