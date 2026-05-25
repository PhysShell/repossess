use eyre::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub browser: Browser,
    pub seed: Seed,
    pub canary: Canary,
    pub crypto: Crypto,
    pub lock: LockCfg,
    pub stores: Vec<StoreCfg>,
    #[serde(default)]
    pub export: ExportCfg,
    #[serde(default)]
    pub workloads: Vec<WorkloadCfg>,
}

#[derive(Debug, Deserialize)]
pub struct Browser {
    pub chromium_bin: PathBuf,
    pub user_data_dir: PathBuf,
    #[serde(default = "default_true")]
    pub headless: bool,
}

#[derive(Debug, Deserialize)]
pub struct Seed {
    pub login_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Canary {
    pub url: String,
    pub expected_status: u16,
    pub field: String,
    pub expected_value: String,
    /// Sent as the canary request's User-Agent. A bare reqwest UA gets 403/404
    /// from WAFs and many JSON APIs; a realistic browser UA avoids that. Not
    /// an anti-bot bypass — just "don't look like a broken curl".
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Extra request headers (e.g. `Accept`, `Origin`). Anything set here
    /// overrides the built-in defaults for the same header name.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct Crypto {
    pub recipient_file: PathBuf,
    pub verify_pubkey_file: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct LockCfg {
    pub ttl_seconds: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoreCfg {
    S3 {
        name: String,
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        access_key_env: String,
        secret_key_env: String,
    },
    GithubRelease {
        name: String,
        repo: String,
        token_env: String,
    },
    GitBranch {
        name: String,
        repo_url: String,
        branch: String,
        token_env: String,
    },
}

impl StoreCfg {
    pub fn name(&self) -> &str {
        match self {
            StoreCfg::S3 { name, .. }
            | StoreCfg::GithubRelease { name, .. }
            | StoreCfg::GitBranch { name, .. } => name,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("parse config {}", path.display()))?;

        // Resolve relative paths against the config file's directory so the
        // repossess can be invoked from any working directory.
        //
        // canonicalize() can only fail here if the file vanished between the
        // read above and now (TOCTOU) or on a permission/symlink anomaly.
        // Surface that explicitly instead of silently leaving paths relative
        // to CWD — a silent fallback would resolve crypto/key files against
        // the wrong directory and fail later with a confusing "file not found".
        let base = path
            .canonicalize()
            .with_context(|| format!("canonicalize config path {}", path.display()))?;
        let base = base.parent().unwrap_or(Path::new("."));
        let resolve = |p: PathBuf| if p.is_relative() { base.join(p) } else { p };
        cfg.browser.chromium_bin = resolve(cfg.browser.chromium_bin);
        cfg.browser.user_data_dir = resolve(cfg.browser.user_data_dir);
        cfg.crypto.recipient_file = resolve(cfg.crypto.recipient_file);
        cfg.crypto.verify_pubkey_file = resolve(cfg.crypto.verify_pubkey_file);

        if let Ok(bin) = std::env::var("CHROMIUM_BIN") {
            cfg.browser.chromium_bin = PathBuf::from(bin);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Surface configuration mistakes that would otherwise blow up deep in the
    /// pipeline (`stores[0]` panicking on empty list, zero-TTL locks expiring
    /// immediately, etc.) as a single descriptive error at startup.
    fn validate(&self) -> Result<()> {
        eyre::ensure!(
            !self.stores.is_empty(),
            "config: stores must contain at least one entry (the primary)"
        );
        eyre::ensure!(
            self.lock.ttl_seconds > 0,
            "config: lock.ttl_seconds must be > 0 (lock with TTL=0 expires immediately and provides no mutual exclusion)"
        );
        Ok(())
    }

    pub fn primary(&self) -> &StoreCfg {
        &self.stores[0]
    }

    pub fn mirrors(&self) -> &[StoreCfg] {
        &self.stores[1..]
    }
}

fn default_true() -> bool {
    true
}

/// A current, realistic desktop Chrome UA. Bump occasionally; a stale UA is
/// itself a (mild) signal, but any plausible browser UA beats `reqwest/x.y`.
pub fn default_user_agent() -> String {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/131.0.0.0 Safari/537.36"
        .to_string()
}

#[derive(Debug, Deserialize)]
pub struct ExportCfg {
    #[serde(default = "default_chatgpt_base_url")]
    pub chatgpt_base_url: String,
    /// Minimum delay between consecutive API calls (ms).
    #[serde(default = "default_rate_limit_delay_ms")]
    pub rate_limit_delay_ms: u64,
    /// Max retries on HTTP 429 before giving up.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Object-store key prefix for exported files.
    #[serde(default = "default_export_prefix")]
    pub prefix: String,
}

impl Default for ExportCfg {
    fn default() -> Self {
        Self {
            chatgpt_base_url: default_chatgpt_base_url(),
            rate_limit_delay_ms: default_rate_limit_delay_ms(),
            max_retries: default_max_retries(),
            prefix: default_export_prefix(),
        }
    }
}

fn default_chatgpt_base_url() -> String { "https://chatgpt.com".into() }
fn default_rate_limit_delay_ms() -> u64 { 2000 }
fn default_max_retries() -> u32 { 5 }
fn default_export_prefix() -> String { "exports/".into() }

// ── Workloads ────────────────────────────────────────────────────────────────
//
// Workloads are the actual jobs the daily `run` performs once the session has
// been restored and the canary has passed. Each one is config-driven and gets
// a shared `WorkloadCtx` (http client w/ cookies, stores, age keys).

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkloadCfg {
    /// Daily incremental sync of ChatGPT conversations.
    ChatgptChats(ChatgptChatsCfg),
}

impl WorkloadCfg {
    pub fn name(&self) -> &str {
        match self {
            WorkloadCfg::ChatgptChats(c) => &c.name,
        }
    }
}

/// All knobs for the ChatGPT chats workload live here so URLs, rate limits
/// and storage layout can change without a rebuild. Defaults track the values
/// from the JS exporter's `rate_limit.js` — tuned to walk ~2000 conversations
/// without tripping the API's per-IP throttles.
#[derive(Debug, Deserialize, Clone)]
pub struct ChatgptChatsCfg {
    pub name: String,
    /// Object-store key prefix. Index → `{prefix}index.json.age`,
    /// conversations → `{prefix}conv/<id>.json.zst.age`.
    #[serde(default = "default_chats_prefix")]
    pub prefix: String,

    // URLs.
    #[serde(default = "default_chatgpt_base_url")]
    pub base_url: String,
    #[serde(default = "default_session_path")]
    pub session_path: String,
    #[serde(default = "default_list_path")]
    pub list_path: String,
    #[serde(default = "default_detail_path_template")]
    pub detail_path_template: String,

    // Pagination.
    #[serde(default = "default_list_page_limit")]
    pub list_page_limit: u32,
    /// Stop list pagination after seeing this many consecutive items that
    /// already match our index (same id + same update_time). Cheap incremental
    /// resume — we don't paginate to the end every day.
    #[serde(default = "default_incremental_stop_after_known")]
    pub incremental_stop_after_known: u32,

    // Rate limits — names mirror rate_limit.js so the JS exporter and this
    // workload can share a tuning intuition.
    #[serde(default = "default_list_delay_ms")]
    pub list_delay_ms: u64,
    #[serde(default = "default_detail_delay_ms")]
    pub detail_delay_ms: u64,
    #[serde(default = "default_detail_batch_size")]
    pub detail_batch_size: u32,
    #[serde(default = "default_detail_batch_cooldown_ms")]
    pub detail_batch_cooldown_ms: u64,
    #[serde(default = "default_retry_sweep_cooldown_ms")]
    pub retry_sweep_cooldown_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// zstd compression level for per-conversation bodies. Defaults to 19
    /// (boundary above which long-distance matching kicks in by default) —
    /// good ratio for small JSON bodies without burning excessive CPU.
    #[serde(default = "default_zstd_level")]
    pub zstd_level: i32,
}

fn default_chats_prefix() -> String { "chatgpt/".into() }
fn default_session_path() -> String { "/api/auth/session".into() }
fn default_list_path() -> String { "/backend-api/conversations".into() }
fn default_detail_path_template() -> String { "/backend-api/conversation/{id}".into() }
fn default_list_page_limit() -> u32 { 28 }
fn default_incremental_stop_after_known() -> u32 { 50 }
fn default_list_delay_ms() -> u64 { 1200 }
fn default_detail_delay_ms() -> u64 { 4000 }
fn default_detail_batch_size() -> u32 { 75 }
fn default_detail_batch_cooldown_ms() -> u64 { 45_000 }
fn default_retry_sweep_cooldown_ms() -> u64 { 600_000 }
fn default_max_backoff_ms() -> u64 { 900_000 }
fn default_zstd_level() -> i32 { 19 }

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    fn config_with_stores(stores_toml: &str) -> String {
        format!(
            r#"
[browser]
chromium_bin = "/usr/bin/chromium"
user_data_dir = "/tmp/ud"

[seed]
login_url = "https://example.com/login"

[canary]
url = "https://example.com/api/me"
expected_status = 200
field = "/user/id"
expected_value = "me"

[crypto]
recipient_file = "/tmp/age-recipient.txt"
verify_pubkey_file = "/tmp/sign-pubkey.hex"

[lock]
ttl_seconds = 300

{stores_toml}
"#
        )
    }

    const ONE_STORE: &str = r#"[[stores]]
kind = "git_branch"
name = "primary"
repo_url = "https://github.com/example/repo"
branch = "state"
token_env = "GH_TOKEN"
"#;

    #[test]
    fn valid_config_loads() {
        let f = write_config(&config_with_stores(ONE_STORE));
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.primary().name(), "primary");
        assert_eq!(cfg.mirrors().len(), 0);
        assert_eq!(cfg.lock.ttl_seconds, 300);
        assert!(cfg.browser.headless);
    }

    #[test]
    fn multiple_stores_separates_primary_and_mirrors() {
        let stores = r#"[[stores]]
kind = "git_branch"
name = "primary"
repo_url = "https://github.com/example/repo"
branch = "state"
token_env = "GH_TOKEN"

[[stores]]
kind = "git_branch"
name = "mirror1"
repo_url = "https://github.com/example/mirror"
branch = "state"
token_env = "GH_MIRROR_TOKEN"
"#;
        let f = write_config(&config_with_stores(stores));
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.primary().name(), "primary");
        assert_eq!(cfg.mirrors().len(), 1);
        assert_eq!(cfg.mirrors()[0].name(), "mirror1");
    }

    #[test]
    fn empty_stores_rejected() {
        let f = write_config(&config_with_stores(""));
        let err = Config::load(f.path()).expect_err("empty stores should fail");
        // Use {:#} to include the full cause chain; the TOML or validation error
        // will name the missing 'stores' field somewhere in that chain.
        let full = format!("{err:#}");
        assert!(full.contains("stores"), "expected 'stores' in error chain: {full}");
    }

    #[test]
    fn zero_ttl_rejected() {
        let content = config_with_stores(ONE_STORE).replace("ttl_seconds = 300", "ttl_seconds = 0");
        let f = write_config(&content);
        let err = Config::load(f.path()).unwrap_err();
        assert!(err.to_string().contains("ttl_seconds"), "{err}");
    }

    #[test]
    fn relative_paths_resolved_against_config_dir() {
        let content = config_with_stores(ONE_STORE)
            .replace(
                "recipient_file = \"/tmp/age-recipient.txt\"",
                "recipient_file = \"age-recipient.txt\"",
            )
            .replace(
                "verify_pubkey_file = \"/tmp/sign-pubkey.hex\"",
                "verify_pubkey_file = \"sign-pubkey.hex\"",
            );
        let f = write_config(&content);
        let config_dir = f.path().canonicalize().unwrap();
        let config_dir = config_dir.parent().unwrap();
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.crypto.recipient_file, config_dir.join("age-recipient.txt"));
        assert_eq!(cfg.crypto.verify_pubkey_file, config_dir.join("sign-pubkey.hex"));
    }

    #[test]
    fn export_defaults_when_section_absent() {
        let f = write_config(&config_with_stores(ONE_STORE));
        let cfg = Config::load(f.path()).unwrap();
        assert_eq!(cfg.export.rate_limit_delay_ms, 2000);
        assert_eq!(cfg.export.max_retries, 5);
        assert_eq!(cfg.export.prefix, "exports/");
    }

    #[test]
    fn store_cfg_name_all_variants() {
        assert_eq!(
            StoreCfg::GitBranch {
                name: "gb".into(),
                repo_url: "u".into(),
                branch: "b".into(),
                token_env: "T".into(),
            }
            .name(),
            "gb"
        );
        assert_eq!(
            StoreCfg::S3 {
                name: "s3".into(),
                endpoint: "e".into(),
                region: "r".into(),
                bucket: "b".into(),
                prefix: "p".into(),
                access_key_env: "A".into(),
                secret_key_env: "S".into(),
            }
            .name(),
            "s3"
        );
        assert_eq!(
            StoreCfg::GithubRelease {
                name: "gh".into(),
                repo: "r".into(),
                token_env: "T".into(),
            }
            .name(),
            "gh"
        );
    }
}
