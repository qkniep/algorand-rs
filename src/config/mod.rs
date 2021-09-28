// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

//mod buildvars;
mod consensus;
mod default;
mod keyfile;
//mod migrate;
//mod version;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::{fs, io};

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol;
pub use consensus::*;

/// Identifies the 'development network' for development and not generally accessible publicly.
pub const DEVNET: protocol::NetworkID = "devnet";

/// Identifies the 'beta network' for early releases of feature to the public prior to releasing these to mainnet/testnet.
pub const BETANET: protocol::NetworkID = "betanet";

/// Identifies the 'development network for tests' for running tests against development and not generally accessible publicly.
pub const DEVTESTNET: protocol::NetworkID = "devtestnet";

/// Identifies the publicly-available test network.
pub const TESTNET: protocol::NetworkID = "testnet";

/// Identifies the publicly-available real-money network.
pub const MAINNET: protocol::NetworkID = "mainnet";

/// The name of the file containing the genesis block.
pub const GENESIS_JSON_FILE: &str = "genesis.json";

// Bit flags for enabling different DNSSEC checks.
const DNSSEC_SRV: u32 = 1;
const DNSSEC_RELAY_ADDR: u32 = 2;
const DNSSEC_TELEMETRY_ADDR: u32 = 4;

/// Max amount of time to spend on generating a proposal block. This should eventually have it's own configurable value.
const PROPOSAL_ASSEMBLY_TIME: std::time::Duration = std::time::Duration::from_millis(250);

// Bit flags for enabling different parts of catchup validation.
const CATCHUP_VALIDATION_MODE_CERTIFICATE: u32 = 1;
const CATCHUP_VALIDATION_MODE_PAYSET_HASH: u32 = 2;
const CATCHUP_VALIDATION_MODE_VERIFY_TX_SIGNATURES: u32 = 4;
const CATCHUP_VALIDATION_MODE_VERIFY_APPLY_DATA: u32 = 8;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("reading/writing configuration failed")]
    IoError(#[from] io::Error),
    #[error("JSON (de)serialization failed")]
    SerializationError(#[from] serde_json::Error),
    //#[error("failed migrating between configs")]
    //MigrateConfigError(#[from] migrate::MigrationError),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

/// Local holds the per-node-instance configuration settings for the protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct Local {
    /// Tracks the current version of the defaults so we can migrate old -> new
    /// This is specifically important whenever we decide to change the default value
    /// for an existing parameter. This field tag must be updated any time we add a new version.
    // TODO properly support versioning (with defaults)???
    //      but this needs not be compatible with go-algorand, right!?
    pub version: u32,

    /// environmental (may be overridden)
    /// When enabled, stores blocks indefinitally, otherwise, only the most recents blocks
    /// are being kept around. ( the precise number of recent blocks depends on the consensus parameters )
    pub archival: bool,

    /// How many peers to propagate to?
    pub gossip_fanout: u32,
    pub net_address: String,

    /// 1 * time.Minute = 60000000000 ns
    pub reconnect_time: std::time::Duration,

    /// What we should tell peers to connect to.
    pub public_address: String,

    pub max_connections_per_ip: i32,

    /// 0 == disable
    pub peer_ping_period_seconds: i32,

    // for https serving
    pub tls_cert_file: String,
    pub tls_key_file: String,

    // Logging
    pub base_logger_debug_level: u32,
    /// If this is 0, do not produce agreement.cadaver.
    pub cadaver_size_target: u64,

    /// Specifies the max number of long-lived incoming connections.
    ///    0 - no connections allowed
    ///   -1 - unbounded
    pub incoming_connections_limit: i32,

    /// Specifies the number of connections that will receive broadcast (gossip) messages from this node.
    /// If the node has more connections than this number, it will send broadcasts to the top connections by priority
    /// (outgoing connections first, then by money held by peers based on their participation key).
    ///    0 - no outgoing messages (not even transaction broadcasting to outgoing peers)
    ///   -1 - unbounded (default)
    pub broadcast_connections_limit: i32,

    /// Specifies that this node should announce its participation key (with the largest stake) to its gossip peers.
    /// This allows peers to prioritize our connection, if necessary, in case of a DoS attack.
    /// Disabling this means that the peers will not have any additional information to allow them to prioritize our
    /// connection.
    pub announce_participation_key: bool,

    /// Specifies peer IP addresses that should always get outgoing broadcast messages from this node.
    pub priority_peers: HashMap<String, bool>,

    /// To make sure the algod process does not run out of FDs, algod ensures
    /// that RLIMIT_NOFILE exceeds the max number of incoming connections (i.e.,
    /// IncomingConnectionsLimit) by at least ReservedFDs.
    /// ReservedFDs are meant to leave room for short-lived FDs like DNS queries, SQLite files, etc.
    pub reserved_fds: u64,

    // local server
    /// API endpoint address
    pub endpoint_address: String,

    // timeouts passed to the rest http.Server implementation
    pub rest_read_timeout_seconds: i32,
    pub rest_write_timeout_seconds: i32,

    /// SRV-based phonebook
    pub dns_bootstrap_id: String,

    /// Log file size limit in bytes
    pub log_size_limit: u64,

    /// text/template for creating log archive filename.
    /// Available template vars:
    /// Time at start of log: {{.Year}} {{.Month}} {{.Day}} {{.Hour}} {{.Minute}} {{.Second}}
    /// Time at end of log: {{.EndYear}} {{.EndMonth}} {{.EndDay}} {{.EndHour}} {{.EndMinute}} {{.EndSecond}}
    ///
    /// If the filename ends with .gz or .bz2 it will be compressed.
    ///
    /// default: "node.archive.log" (no rotation, clobbers previous archive)
    pub log_archive_name: String,

    /// Will be parsed by time.ParseDuration().
    /// Valid units are 's' seconds, 'm' minutes, 'h' hours
    // TODO adapt doc to Rust implementation
    pub log_archive_max_age: String,

    /// number of consecutive attempts to catchup after which we replace the peers we're connected to
    pub catchup_failure_peer_refresh_rate: i32,

    /// where should the node exporter listen for metrics
    pub node_exporter_listen_address: String,

    /// enable reporting of metrics (such as ...)
    pub enable_metric_reporting: bool,

    /// enable top accounts reporting flag
    pub enable_top_accounts_reporting: bool,

    /// enable agreement reporting flag. Currently only prints additional period events.
    pub enable_agreement_reporting: bool,

    /// enable agreement timing metrics flag
    pub enable_agreement_time_metrics: bool,

    /// Path to the node exporter.
    pub node_exporter_path: String,

    /// Fallback DNS resolver address that would be used if the system resolver would fail to retrieve SRV records
    pub fallback_dns_resolver_address: String,

    /// Exponential increase factor of transaction pool's fee threshold.
    /// Should always be 2 in production!
    pub tx_pool_exponential_increase_factor: u64,

    pub suggested_fee_block_history: i32,

    /// Number of transactions that fit in the transaction pool.
    pub tx_pool_size: i32,

    /// Number of seconds allowed for syncing transactions.
    pub tx_sync_timeout_seconds: i64,

    /// Number of seconds between transaction synchronizations.
    pub tx_sync_interval_seconds: i64,

    /// Number of incoming message hashes buckets.
    pub incoming_message_filter_bucket_count: i32,

    /// Size of each incoming message hash bucket.
    pub incoming_message_filter_bucket_size: i32,

    /// Number of outgoing message hashes buckets.
    pub outgoing_message_filter_bucket_count: i32,

    /// Size of each outgoing message hash bucket.
    pub outgoing_message_filter_bucket_size: i32,

    /// Enable the filtering of outgoing messages.
    pub enable_outgoing_network_message_filtering: bool,

    /// Enable the filtering of incoming messages.
    pub enable_incoming_message_filter: bool,

    /// Control enabling / disabling deadlock detection.
    /// Set to negative (-1) to disable, positive (1) to enable, 0 for default.
    pub deadlock_detection: i32,

    /// Prefer to run algod Hosted (under algoh)
    /// Observed by `goal` for now.
    // TODO adapt doc
    pub run_hosted: bool,

    /// The max number of blocks that catchup will fetch in parallel.
    /// If less than Protocol.seed_lookback, then Protocol.seed_lookback will be used as to limit the catchup.
    /// Setting this variable to 0 would disable the catchup.
    pub catchup_parallel_blocks: u64,

    /// Generate `assemble_block_metrics` telemetry events.
    pub enable_assemble_stats: bool,

    /// Generate `process_block_metrics` telemetry events.
    pub enable_process_block_stats: bool,

    /// Number of past blocks that will be considered in computing the suggested fee.
    pub suggested_fee_sliding_window_size: u32,

    /// Max size the sync server would return.
    pub tx_sync_serve_response_size: i32,

    /// Indicates whether to activate the indexer for fast retrieval of transactions.
    /// Note -- Indexer cannot operate on non-archival nodes.
    pub is_indexer_active: bool,

    /// Indicates whether or not the node should use the X-Forwarded-For HTTP Header when determining
    /// the source of a connection.  If used, it should be set to the string "X-Forwarded-For",
    /// unless the proxy vendor provides another header field.
    /// In the case of cloud_flare proxy, the "CF-Connecting-IP" header field can be used.
    pub use_xforwarded_for_address_field: String,

    /// Indicates whether the network library relay messages even in the case that no net_address was specified.
    pub force_relay_messages: bool,

    /// Used in conjunction with `connections_rate_limiting_count`;
    /// see `connections_rate_limiting_count` description for further information.
    /// Providing a zero value in this variable disables the connection rate limiting.
    pub connections_rate_limiting_window_seconds: u32,

    /// Used along with `connections_rate_limiting_window_seconds` to determine if a connection request should be
    /// accepted or not. The gossip network examine all the incoming requests in the past
    /// `connections_rate_limiting_window_seconds` seconds that share the same origin.
    /// If the total count exceed the `connections_rate_limiting_count` value, the connection is refused.
    pub connections_rate_limiting_count: u32,

    /// Enables the logging of the incoming requests to the telemetry server.
    pub enable_request_logger: bool,

    /// Defines the interval (in seconds) at which the peer connections information is being sent to the telemetry
    /// (if enabled).
    pub peer_connections_update_interval: i32,

    /// Enables the go pprof endpoints, should be false if the algod api will be exposed to untrusted individuals.
    pub enable_profiler: bool,

    /// Records messages to node.log that are normally sent to remote event monitoring.
    pub telemetry_to_log: bool,

    /// Instructs algod validating DNS responses.
    /// Possible flag values
    /// 0x00 - disabled
    /// 0x01 (dnssec_sRV) - validate SRV response
    /// 0x02 (dnssec_relay_addr) - validate relays' names to addresses resolution
    /// 0x04 (dnssec_telemetry_addr) - validate telemetry and metrics names to addresses resolution
    /// ...
    pub dns_security_flags: u32,

    /// Controls whether the gossip node would respond to ping messages with a pong message.
    pub enable_ping_handler: bool,

    /// Disables the connection throttling of the network library, which allow the network library to continuesly
    /// disconnect relays based on their relative (and absolute) performance.
    pub disable_outgoing_connection_throttling: bool,

    /// Overrides network protocol version (if present).
    pub network_protocol_version: String,

    /// Sets the interval at which catchpoint are being generated.
    /// Setting this to 0 disables the catchpoint from being generated.
    /// See `catchpoint_tracking` for more details.
    pub catchpoint_interval: u64,

    /// Defines how many recent catchpoint files we want to store.
    ///    0 - don't store any
    ///   -1 - unlimited
    pub catchpoint_file_history_length: i32,

    /// Enables the ledger serving service.
    /// The functionality of this depends on `net_address`, which must also be provided.
    /// This functionality is required for the catchpoint catchup.
    pub enable_ledger_service: bool,

    /// Enables the block serving service.
    /// The functionality of this depends on `net_address`, which must also be provided.
    /// This functionality is required for the catchup.
    pub enable_block_service: bool,

    /// Enables the block serving service over the gossip network.
    /// The functionality of this depends on `net_address`, which must also be provided.
    /// This functionality is required for the relays to perform catchup from nodes.
    pub enable_gossip_block_service: bool,

    /// Controls how long the HTTP query for fetching a block from a relay would take
    /// before giving up and trying another relay.
    pub catchup_http_block_fetch_timeout_sec: i32,

    /// Controls how long the gossip query for fetching a block from a relay would take
    /// before giving up and trying another relay.
    pub catchup_gossip_block_fetch_timeout_sec: i32,

    /// Controls the number of attempt the ledger fetching would be attempted
    /// before giving up catching up to the provided catchpoint.
    pub catchup_ledger_download_retry_attempts: i32,

    /// catchup_ledger_download_retry_attempts controls the number of attempt the block fetching would be attempted before giving up catching up to the provided catchpoint.
    pub catchup_block_download_retry_attempts: i32,

    /// Enables teal/compile, teal/dryrun API endpoints.
    /// This functionality is disabled by default.
    pub enable_developer_api: bool,

    /// Controls whether the accounts database should be optimized on algod startup.
    pub optimize_accounts_database_on_startup: bool,

    /// Determines if catchpoints are going to be tracked.
    ///   -1 - don't track catchpoints
    ///    1 - track catchpoints as long as `catchpoint_interval` is also set to a positive non-zero value
    ///        If `catchpoint_interval` <= 0, no catchpoint tracking would be performed.
    ///    0 - automatic (default)
    ///        In this mode, a non-archival node would not track the catchpoints,
    ///        and an archival node would track the catchpoints as long as `catchpoint_interval` > 0.
    /// Other values give a warning in the log file and behave as if the default value was provided.
    pub catchpoint_tracking: i64,

    /// Defines the synchronous mode used by the ledger database.
    /// The supported options are:
    ///   0 - SQLite continues without syncing as soon as it has handed data off to the operating system.
    ///   1 - SQLite database engine will still sync at the most critical moments, but less often than in FULL mode.
    ///   2 - SQLite database engine will use the x_sync method of the VFS to ensure that all content is safely written
    ///       to disk prior to continuing. On Mac OS, the data is additionally syncronized via fullfsync.
    ///   3 - In addition to what being done in 2, it provides additional durability if the commit is followed closely
    ///       by a power loss.
    /// For further information see the description of `synchronous_mode` in `dbutil.rs`.
    pub ledger_synchronous_mode: i32,

    /// Defines the synchronous mode used by the ledger database while the account database is being rebuilt.
    /// This is not a typical operational usecase, and is expected to happen only on either startup
    /// (after enabling the catchpoint interval, or on certain database upgrades) or during fast catchup.
    /// The values specified here and their meanings are identical to the ones in `ledger_synchronous_mode`.
    pub accounts_rebuild_synchronous_mode: i32,

    /// Defines the maximum duration a client will be keeping the outgoing connection of a catchpoint download request
    /// open for processing before shutting it down. Networks that have large catchpoint files, slow connection or slow
    /// storage could be a good reason to increase this value. Note that this is a client-side only configuration value,
    /// and it's independent of the actual catchpoint file size.
    pub max_catchpoint_download_duration: std::time::Duration,

    /// Defines the minimal download speed that would be considered to be "acceptable" by the catchpoint file fetcher,
    /// measured in bytes per seconds.
    /// If the provided stream speed drops below this threshold, the connection would be recycled.
    /// Note that this field is evaluated per catchpoint "chunk" and not on it's own.
    /// If this field is zero, the default of 20480 would be used.
    pub min_catchpoint_file_download_bytes_per_second: u64,

    /// An address given as "<host>:<port>" to report graph propagation trace info to.
    pub network_message_trace_server: String,

    /// Defines the number of transactions that the verified transactions cache would hold
    /// before cycling the cache storage in a round-robin fashion.
    pub verified_transcations_cache_size: i32,

    /// Controls which peers the catchup service would use in order to catchup.
    /// When enabled, the catchup service would use the archive servers before falling back to the relays.
    /// On networks that doesn't have archive servers, this becomes a no-op, as the catchup service would have no
    /// archive server to pick from, and therefore automatically selects one of the relay nodes.
    pub enable_catchup_from_archive_servers: bool,

    /// Controls whether the incoming connection rate limit would apply for
    /// connections that are originating from the local machine. Setting this to "true", allow to create large
    /// local-machine networks that won't trip the incoming connection limit observed by relays.
    pub disable_localhost_connection_rate_limit: bool,

    /// Comma delimited list of endpoints which the block service uses to
    /// redirect the http requests to in case it does not have the round.
    /// If it is not specified, will check enable_block_service_fallback_to_archiver.
    pub block_service_custom_fallback_endpoints: String,

    /// Controls whether the block service redirects the http requests to
    /// an archiver or return status_not_found (404) when in does not have the requested round,
    /// and block_service_custom_fallback_endpoints is empty.
    /// The archiver is randomly selected, if none is available, will return status_not_found (404).
    pub enable_block_service_fallback_to_archiver: bool,

    /// Development and testing configuration used by the catchup service.
    /// It can be used to omit certain validations to speed up the catchup process,
    /// or to apply extra validations which are redundant in normal operation.
    /// This field is a bit-field with:
    /// bit 0: (default 0) 0: verify the block certificate; 1: skip this validation
    /// bit 1: (default 0) 0: verify payset committed hash in block header matches payset hash; 1: skip this validation
    /// bit 2: (default 0) 0: don't verify the transaction signatures on the block are valid;
    ///                    1: verify the transaction signatures on block
    /// bit 3: (default 0) 0: don't verify that the hash of the recomputed payset matches the hash of the payset
    ///                       committed in the block header;
    ///                    1: do perform the above verification
    /// Note: not all permutations of the above bitset are currently functional. In particular, the ones that are functional are:
    ///   0  - default behavior
    ///   3  - speed up catchup by skipping necessary validations
    ///   12 - perform all validation methods (normal and additional)
    ///        These extra tests helps to verify the integrity of the compiled executable against previously used executabled,
    ///        and would not provide any additional security guarantees.
    pub catchup_block_validate_mode: u32,

    /// Generate account_updates telemetry event
    pub enable_account_updates_stats: bool,

    /// Time interval in nanoseconds for generating account_updates telemetry event
    pub account_updates_stats_interval: std::time::Duration,

    /// Duration between two consecutive checks to see if new participation
    /// keys have been placed on the genesis directory.
    pub participation_keys_refresh_interval: std::time::Duration,

    /// Disables all the incoming and outgoing communication a node would perform.
    /// This is useful when we have a single-node private network,
    /// where there is no other nodes that need to be communicated with.
    /// features like catchpoint catchup would be rendered completly non-operational,
    /// and many of the node inner working would be completly dis-functional.
    pub disable_networking: bool,
}

// Filenames of config files within the configdir (e.g. ~/.algorand)

/// Name of the config.json file where we store per-algod-instance settings.
const CONFIG_FILENAME: &str = "config.json";

/// PhonebookFilename is the name of the phonebook configuration files (no longer used).
const PHONEBOOK_FILENAME: &str = "phonebook.json"; // no longer used in product - still in tests

/// Prefix of the name of the ledger database files.
const LEDGER_FILENAME_PREFIX: &str = "ledger";

/// Name of the agreement database file.
/// It is used to recover from node crashes.
const CRASH_FILENAME: &str = "crash.sqlite";

/// Name of the compact certificate database file.
/// It is used to track in-progress compact certificates.
const COMPACT_CERT_FILENAME: &str = "compactcert.sqlite";

/// Defines a set of consensus prototocols that are to be loaded from the data directory (if present),
/// to override the built-in supported consensus protocols.
const CONFIGURABLE_CONSENSUS_PROTOCOLS_FILENAME: &str = "consensus.json";

impl Local {
    /// Returns a Local config structure based on merging the defaults
    /// with settings loaded from the config file from the custom dir.
    /// If the custom file cannot be loaded, the default config is returned
    /// (with the error from loading the custom file).
    fn load_from_disk(custom: &impl AsRef<OsStr>) -> Result<Self> {
        Self::load_from_file(&Path::new(&custom).join(CONFIG_FILENAME))
    }

    fn load_from_file(file: &impl AsRef<Path>) -> Result<Self> {
        let mut c = Self {
            version: 0, // Set to 0 so we get the version from the loaded file.
            ..Self::default()
        };
        c.merge_from_file(file)?;

        // Migrate in case defaults were changed
        // If a config file does not have version, it is assumed to be zero.
        // All fields listed in migrate() might be changed if an actual value matches to default value from a previous version.
        // TODO reimplement migrate
        //migrate::migrate(c)?;
        Ok(c)
    }

    fn merge_from_dir(&mut self, root: &impl AsRef<OsStr>) -> Result<()> {
        self.merge_from_file(&Path::new(&root).join(CONFIG_FILENAME))
    }

    fn merge_from_file(&mut self, full_path: &impl AsRef<Path>) -> Result<()> {
        let content = fs::read_to_string(full_path)?;
        self.load(&content)?;

        // For now, all relays (listening for incoming connections) are also Archival.
        // We can change this logic in the future, but it's currently the sanest default.
        if !self.net_address.is_empty() {
            self.archival = true;
            self.enable_ledger_service = true;
            self.enable_block_service = true;
        }

        Ok(())
    }

    fn load(&mut self, content: &str) -> io::Result<()> {
        *self = serde_json::from_str(content)?;
        Ok(())
    }

    /// Returns an array of one or more DNS Bootstrap identifiers.
    fn dns_bootsrap_array(&self, network: protocol::NetworkID) -> Vec<String> {
        let dns_str = self.dns_bootstrap(network);
        let array = dns_str.split(';');
        // omit zero length entries from the result set.
        array
            .into_iter()
            .filter(|e| !e.is_empty())
            .map(|s| s.to_owned())
            .collect()
    }

    /// Returns the network-specific DNSBootstrap identifier.
    fn dns_bootstrap(&self, network: protocol::NetworkID) -> String {
        // if user hasn't modified the default dns_bootstrap_id in the configuration
        // file and we're targeting a devnet (via genesis file),
        // we the explicitly set devnet network bootstrap.
        if self.dns_bootstrap_id == Local::default().dns_bootstrap_id {
            match network {
                DEVNET => return "devnet.algodev.network".to_owned(),
                BETANET => return "betanet.algodev.network".to_owned(),
                _ => {}
            }
        }
        self.dns_bootstrap_id.replace("<network>", network)
    }

    /// Writes the Local settings into a root/ConfigFilename file.
    pub fn save_to_disk(&self, root: &str) -> io::Result<()> {
        let configpath = Path::new(root).join(CONFIG_FILENAME);
        let configpath_str = configpath.into_os_string().into_string().unwrap();
        let expanded_path = shellexpand::env(&configpath_str);
        self.save_to_file(&expanded_path.unwrap())
    }

    /// Saves the config to a specific filename, allowing overriding the default name.
    // TODO actually write to file once util/codecs is implemented
    pub fn save_to_file(&self, filename: &str) -> io::Result<()> {
        Ok(())
        /*return codecs.SaveNonDefaultValuesToFile(
            filename,
            cfg,
            DEFAULT_LOCAL,
            vec!["Version".to_owned()],
            true,
        );*/
    }

    /// Returns true iff SRV response verification enforced.
    pub fn dnssec_srv_enforced(&self) -> bool {
        self.dns_security_flags & DNSSEC_SRV != 0
    }

    /// Returns true iff relay name to ip addr resolution enforced.
    pub fn dnssec_relay_addr_enforced(&self) -> bool {
        self.dns_security_flags & DNSSEC_RELAY_ADDR != 0
    }

    /// Returns true iff relay name to ip addr resolution enforced.
    pub fn dnssec_telemetry_enforced(&self) -> bool {
        self.dns_security_flags & DNSSEC_TELEMETRY_ADDR != 0
    }

    /// Returns true iff certificate verification is needed.
    // TODO why here "== 0"...
    pub fn catchup_verify_certificate(&self) -> bool {
        self.catchup_block_validate_mode & CATCHUP_VALIDATION_MODE_CERTIFICATE == 0
    }

    /// Returns true iff payset hash verification is needed.
    pub fn catchup_verify_payset_hash(&self) -> bool {
        self.catchup_block_validate_mode & CATCHUP_VALIDATION_MODE_PAYSET_HASH == 0
    }

    /// Returns true iff transactions signature verification is needed.
    // TODO ...and here "!= 0"???
    pub fn catchup_verify_transaction_signatures(&self) -> bool {
        self.catchup_block_validate_mode & CATCHUP_VALIDATION_MODE_VERIFY_TX_SIGNATURES != 0
    }

    /// Returns true iff verifying the ApplyData of the payset needed.
    pub fn catchup_verify_apply_data(&self) -> bool {
        self.catchup_block_validate_mode & CATCHUP_VALIDATION_MODE_VERIFY_APPLY_DATA != 0
    }
}

/*
impl Default for Local {
    /// Copies the current DEFAULT_LOCAL config.
    fn default() -> Self {
        return DEFAULT_LOCAL;
    }
}
*/

#[derive(Serialize, Deserialize)]
struct PhonebookBlackWhiteList {
    pub include: Vec<String>,
}

/// Returns a phonebook loaded from the provided directory, if it exists.
// NOTE: We no longer use phonebook for anything but tests, but users should be able to use it
pub fn load_phonebook(datadir: &str) -> io::Result<Vec<String>> {
    let entries = Vec::new();
    let path = Path::new(datadir).join(PHONEBOOK_FILENAME);
    let content = fs::read_to_string(path)?;
    //if os.IsNotExist(rootErr) {
    //	//don't return error
    //} else {
    //phonebook := PhonebookBlackWhiteList{}
    serde_json::from_str(&content)?;
    //entries = phonebook.include

    // get an initial list of peers
    Ok(entries)
}

/// Writes the phonebook into a root/PhonebookFilename file.
pub fn save_phonebook_to_disk(entries: Vec<String>, root: &str) -> Result<()> {
    let configpath = Path::new(root).join(PHONEBOOK_FILENAME);
    let configpath_str = configpath.into_os_string().into_string().unwrap();
    let expanded_path = shellexpand::env(&configpath_str);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .read(false)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&*expanded_path.unwrap())?;
    save_phonebook(entries, &mut f)?;
    Ok(())
}

fn save_phonebook(entries: Vec<String>, w: &mut impl io::Write) -> Result<()> {
    let pb = PhonebookBlackWhiteList { include: entries };
    // codecs.NewFormattedJSONEncoder(w)
    Ok(serde_json::to_writer_pretty(w, &pb)?)
}

lazy_static! {
    static ref GLOBAL_CONFIG_FILE_ROOT: RwLock<PathBuf> = RwLock::new(Path::new("").to_path_buf());
}

/// Retrieves the full path to a configuration file.
/// These are global configurations - not specific to data-directory / network.
pub fn get_config_file_path(file: &str) -> Result<PathBuf> {
    Ok(get_global_config_file_root()?.join(file))
}

/// GetGlobalConfigFileRoot returns the current root folder for global configuration files.
/// This will likely only change for tests.
pub fn get_global_config_file_root() -> io::Result<PathBuf> {
    let mut gcfr = GLOBAL_CONFIG_FILE_ROOT.write().unwrap();
    if gcfr.as_os_str().is_empty() {
        *gcfr = get_default_config_file_path()?;
        // TODO use permissions 0o777
        fs::create_dir(gcfr.clone())?;
    }
    Ok(gcfr.clone())
}

/// Allows overriding the root folder for global configuration files.
/// It returns the current one so it can be restored, if desired.
/// This will likely only change for tests.
pub fn set_global_config_file_root(root_path: &impl AsRef<PathBuf>) -> PathBuf {
    let current_root = GLOBAL_CONFIG_FILE_ROOT.read().unwrap().clone();
    *GLOBAL_CONFIG_FILE_ROOT.write().unwrap() = root_path.as_ref().clone();
    current_root
}

/// Retrieves the default directory for global (not per-instance) config files.
/// By default we store these in ~/.algorand/.
/// This will likely only change for tests.
pub fn get_default_config_file_path() -> io::Result<PathBuf> {
    match dirs::home_dir() {
        Some(home_dir) => Ok(Path::new(&home_dir).join(".algorand")),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "current user has no home directory",
        )),
    }
}
