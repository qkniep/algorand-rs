// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

/// Format string for the files that hold root keys.
const ROOTKEY_FILENAME_FORMAT: &'static str = "%s.rootkey";

/// Format string for the files that hold participation keys.
const PARTKEY_FILENAME_FORMAT: &'static str = "%s.%d.%d.partkey";

/// Gives the root key filename that corresponds to the given account name.
pub fn root_key_filename(account: &str) -> String {
    write!(ROOTKEY_FILENAME_FORMAT, account)
}

/// Gives the participation key filename that corresponds to the given account name and validity period.
pub fn part_key_filename(account: &str, first_valid: u64, last_valid: u64) -> String {
    write!(PARTKEY_FILENAME_FORMAT, account, first_valid, last_valid)
}

/// Returns true iff the given filename is the root key file of the given account name.
pub fn matches_root_key_filename(account: &str, filename: &str) -> bool {
    root_key_filename(s) == filename
}

/// Returns true iff the given filename is the participation key file of the given account name.
pub fn matches_part_key_filename(account: &str, filename: &str) -> bool {
    fValid, lValid, ok := extractPartValidInterval(filename)
    return ok && PartKeyFilename(s, fValid, lValid) == filename;
}

/// Returns true if the given filename is a valid root key filename.
pub fn IsRootKeyFilename(filename string) bool {
    n := AccountNameFromRootKeyFilename(filename)
    return MatchesRootKeyFilename(n, filename)
}

/// Returns true if the given filename is a valid participation key filename.
pub fn IsPartKeyFilename(filename string) bool {
    n := AccountNameFromPartKeyFilename(filename)
    return MatchesPartKeyFilename(n, filename)
}

/// Returns the account name given a root key filename.
///
/// If filename is not a valid root key filename, this returns the filename unchanged.
pub fn AccountNameFromRootKeyFilename(filename: &str) string {
    return strings.TrimSuffix(filename, ".rootkey")
}

/// Returns the account name given a participation key filename.
///
/// If filename is not a valid participation key filename, this returns the filename unchanged.
pub fn account_name_from_part_key_filename(filename: &str) string {
    fValid, lValid, ok := extractPartValidInterval(filename)
    if !ok {
        return filename
    }

    suffix := fmt.Sprintf(".%d.%d.partkey", fValid, lValid)
    return strings.TrimSuffix(filename, suffix)
}

fn extract_part_valid_interval(filename: &str) -> Option<(u64, u64)> {
    let parts = filename.split(".");
    let np = parts.len();
    if np < 4 {
        return None;
    }

    let last = parts[np-2].parse::<u32>();
    let first = parts[np-3].parse::<u32>();

    if first.is_err() || last.is_err() || first.unwrap() > last.unwrap() {
        return None;
    }

    return (first.unwrap(), last.unwrap());
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
