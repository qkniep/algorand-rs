#! /bin/sh

# Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
# Distributed under terms of the MIT license.

rustup component add clippy

cargo install cargo-audit --features vendored-libgit2
#cargo install cargo-bloat

# unfortunately this currently only works on nightly
#cargo install cargo-udeps

# gives too many false positives
#cargo install cargo-spellcheck
