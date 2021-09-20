// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//! We are intending to follow the principles set forth by the Semantic Versioning Specification
//! https://semver.org/

use std::fmt;

/// Major semantic version number (#.y.z) - changed when first public release (0.y.z -> 1.y.z)
/// and when backwards compatibility is broken.
const VERSION_MAJOR: i32 = 2;

/// Minor semantic version number (x.#.z) - changed when backwards-compatible features are introduced.
/// Not enforced until after initial public release (x > 0).
const VERSION_MINOR: i32 = 10;

/// Holding our full version information.
struct Version {
    /// Algorand's major version number
    pub major: i32,

    /// Algorand's minor version number
    pub minor: i32,

    /// Algorand's Build Number
    pub build_number: i32,

    /// Suffix for any metadata
    pub suffix: String,

    /// Hash of commit the build is based on
    pub commit_hash: String,

    /// Branch the build is based on
    pub branch: String,

    /// Branch-derived release channel the build is based on
    pub channel: String,

    /// DataDirectory for the current instance
    pub data_directory: String,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build_number)
    }
}

impl Version {
    /// Returns the version number in integer (u64) form.
    pub fn as_u64(&self) -> u64 {
        let version = self.major as u64;
        version <<= 16;
        version |= self.minor as u64;
        version <<= 16;
        version |= self.build_number as u64;
        return version;
    }

    // func (v Version) GetSuffix() string {
    // 	return v.Suffix
    // }

    /// returns the commit ID for the build's source.
    pub fn get_commit_hash(&self) -> String {
        return self.commit_hash;
    }
}

/// Assumes val is valid number value string; panics if it's not.
fn convert_to_int(val: &str) -> i32 {
    if val == "" {
        return 0;
    }
    return val.parse().unwrap();
}

// make this mutable? RwLock?
const CURRENT_VERSION: Version = Version {
    major: VERSION_MAJOR,
    minor: VERSION_MINOR,
    build_number: convert_to_int(BuildNumber), // set using -ldflags
    suffix: "".to_owned(),
    commit_hash: CommitHash,
    branch: Branch,
    channel: Channel,
    data_directory: "".to_owned(),
};

/// Retrieves a copy of the current global Version structure (for the application).
pub fn get_current_version() -> Version {
    CURRENT_VERSION
}

// FormatVersionAndLicense prints current version and license information
pub fn format_version_and_license() -> String {
    let version = get_current_version();
    format!(
        "{}\n{}.{} [{}] (commit #{})\n{}",
        version.as_u64(),
        version,
        version.channel,
        version.branch,
        version.get_commit_hash(),
        get_license_info()
    )
}

/// Allows replacing the current global Version structure (for the application).
pub fn set_current_version(version: Version) {
    currentVersion = version
}

/// Convenience method for setting the data dir on the global Version struct.
/// Used by algod and algoh to set built-time ephemeral version component e.g. data directory.
pub fn update_version_data_dir(data_dir: &str) {
    let mut v = get_current_version();
    v.data_directory = data_dir.to_owned();
    set_current_version(v);
}

/// Retrieves the current version formatted as a simple version string (Major.Minor.BuildNumber).
pub fn get_algorand_version() -> String {
    CURRENT_VERSION.to_string()
}

/// Retrieves the current license information.
pub fn get_license_info() -> String {
    "algorsand is licensed under the MIT license\nsource code is available at https://github.com/qkniep/algorand-rs".to_owned()
}
