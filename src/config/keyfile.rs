// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use crate::data::basics;

/// Gives the root key filename that corresponds to the given account name.
pub fn root_key_filename(account: &str) -> String {
    format!("{}.rootkey", account)
}

/// Gives the participation key filename that corresponds to the given account name and validity period.
pub fn part_key_filename(
    account: &str,
    first_valid: basics::Round,
    last_valid: basics::Round,
) -> String {
    format!("{}.{}.{}.partkey", account, first_valid.0, last_valid.0)
}

/// Returns true iff the given filename is the root key file of the given account name.
pub fn matches_root_key_filename(account: &str, filename: &str) -> bool {
    root_key_filename(account) == filename
}

/// Returns true iff the given filename is the participation key file of the given account name.
pub fn matches_part_key_filename(account: &str, filename: &str) -> bool {
    if let Some((first, last)) = extract_part_valid_interval(filename) {
        part_key_filename(account, first, last) == filename
    } else {
        false
    }
}

/// Returns true iff the given filename is a valid root key filename.
pub fn is_root_key_filename(filename: &str) -> bool {
    let n = account_name_from_part_key_filename(filename);
    return matches_root_key_filename(&n, filename);
}

/// Returns true iff the given filename is a valid participation key filename.
pub fn is_part_key_filename(filename: &str) -> bool {
    let n = account_name_from_part_key_filename(filename);
    return matches_part_key_filename(&n, filename);
}

/// Returns the account name given a root key filename.
///
/// If filename is not a valid root key filename, this returns the filename unchanged.
pub fn account_name_from_root_key_filename(filename: &str) -> String {
    return filename.trim_end_matches(".rootkey").to_owned();
}

/// Returns the account name given a participation key filename.
///
/// If filename is not a valid participation key filename, this returns the filename unchanged.
pub fn account_name_from_part_key_filename(filename: &str) -> String {
    if let Some((first, last)) = extract_part_valid_interval(filename) {
        let suffix = format!(".{}.{}.partkey", first.0, last.0);
        return filename.trim_end_matches(&suffix).to_owned();
    } else {
        return filename.to_owned();
    }
}

fn extract_part_valid_interval(filename: &str) -> Option<(basics::Round, basics::Round)> {
    let parts: Vec<&str> = filename.split(".").into_iter().collect();
    let np = parts.len();
    if np < 4 {
        return None;
    }

    let last = parts[np - 2].parse::<u64>();
    let first = parts[np - 3].parse::<u64>();

    match (first, last) {
        (Ok(f), Ok(l)) if (f <= l) => Some((basics::Round(f), basics::Round(l))),
        _ => None,
    }
}
