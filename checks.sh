#! /bin/sh

# Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
# Distributed under terms of the MIT license.

RED='\u001b[31m'
GRN='\u001b[32m'
BLU='\u001b[34m'
RST='\u001b[0m'

echo -e "${BLU}Running security audit of dependencies (cargo audit)...${RST}"
if cargo audit; then
    echo -e "${GRN}Found no vulnerabilities in included crates.${RST}"
else
    echo -e "${RED}Found vulnerabilities in included crates!${RST}"
    exit 1
fi
echo ""

echo -e "${BLU}Checking if code compiles...${RST}"
if cargo build --all-targets; then
    echo -e "${GRN}Your code successfully compiled.${RST}"
else
    echo -e "${RED}The project did not compile successfully!${RST}"
    echo -e "${RED}Please fix your code before committing.${RST}"
    exit 1
fi
echo ""

echo -e "${BLU}Checking if code is formatted with rustfmt...${RST}"
if rustfmt --check ./src/**/*.rs; then
    echo -e "${GRN}All code is formatted correctly.${RST}"
else
    echo -e "${RED}Found files which are not correctly formatted!${RST}"
    echo -e "${RED}Please run 'cargo fmt' before committing.${RST}"
    exit 1
fi
echo ""

echo -e "${BLU}Asking picky clippy if it's satisfied with your code...${RST}"
if cargo clippy -- -F clippy::suspicious -F clippy::complexity -F clippy::perf -W clippy::pedantic; then
    echo -e "${GRN}Clippy is satisfied.${RST}"
else
    echo -e "${RED}Clippy doesn't like a few things about your code!${RST}"
    echo -e "${RED}Please fix them before committing.${RST}"
    exit 1
fi
echo ""

echo -e "${BLU}Checking if all test cases pass...${RST}"
if cargo test; then
    echo -e "${GRN}All test cases passed.${RST}"
else
    echo -e "${RED}Test case(s) failed!${RST}"
    echo -e "${RED}Please fix your tests and/or code before committing.${RST}"
    exit 1
fi
echo ""

echo -e "${GRN}All checks passed.${RST}"
echo -e "${GRN}You are ready to commit your changes.${RST}"
