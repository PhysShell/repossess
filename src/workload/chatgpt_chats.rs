use eyre::{bail, eyre, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::ChatgptChatsCfg;
use crate::crypto::encrypt;
use crate::snapshot::sha256_hex;
use crate::stores::{self, SnapshotStore};

use super::chatgpt::{ConversationListResponse, ConversationSummary, SessionResponse};
use super::{Workload, WorkloadCtx};

/// What we keep in the encrypted index file. The index lets us cheaply decide
/// "is this conversation already up to date?" without fetching its body, and
/// gives us the storage key + integrity hash for each known conversation.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatsIndex {
    pub schema_version: u32,
    pub updated_at: DateTime<Utc>,
    pub entries: HashMap<String, ChatsIndexEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatsIndexEntry {
    /// API's `update_time` — the change-detection signal. If the list page
    /// reports the same value, we skip the detail fetch.
    pub update_time: Option<f64>,
    pub title: Option<String>,
    pub object_key: String,
    pub sha256: String,
    pub bytes: u64,
    pub stored_at: DateTime<Utc>,
}

impl ChatsIndex {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            updated_at: Utc::now(),
            entries: HashMap::new(),
        }
    }
}

pub struct ChatgptChatsWorkload {
    cfg: ChatgptChatsCfg,
}

impl ChatgptChatsWorkload {
    pub fn new(cfg: ChatgptChatsCfg) -> Self {
        Self { cfg }
    }

    pub fn cfg(&self) -> &ChatgptChatsCfg {
        &self.cfg
    }

    pub fn index_key(&self) -> String {
        format!("{}index.json.age", self.cfg.prefix)
    }

    pub fn conv_key(&self, id: &str) -> String {
        format!("{}conv/{id}.json.zst.age", self.cfg.prefix)
    }

    /// Encrypt + zstd-compress one conversation's raw JSON body. The body is
    /// kept as `serde_json::Value` so that whatever fields ChatGPT happens to
    /// add later (model slugs, moderation, gizmo_id, …) round-trip through
    /// us untouched — losing fields silently would be much worse than failing
    /// loudly.
    pub fn encode_conversation(
        &self,
        value: &serde_json::Value,
        recipient: &age::x25519::Recipient,
    ) -> Result<Bytes> {
        let json = serde_json::to_vec(value).context("serialize conversation")?;
        let compressed = zstd::encode_all(json.as_slice(), self.cfg.zstd_level)
            .context("zstd compress conversation")?;
        encrypt::encrypt(&compressed, recipient).context("encrypt conversation")
    }

    pub fn decode_conversation(
        &self,
        ciphertext: &[u8],
        identity: &age::x25519::Identity,
    ) -> Result<serde_json::Value> {
        let compressed = encrypt::decrypt(ciphertext, identity).context("decrypt conversation")?;
        let json = zstd::decode_all(&compressed[..]).context("zstd decompress conversation")?;
        serde_json::from_slice(&json).context("parse conversation JSON")
    }

    /// Encrypt the index. We don't compress — it's small (a few hundred KB
    /// even with 2k entries) and skipping the zstd layer keeps the on-disk
    /// format the obvious thing: "age over JSON".
    pub fn encode_index(
        &self,
        idx: &ChatsIndex,
        recipient: &age::x25519::Recipient,
    ) -> Result<Bytes> {
        let json = serde_json::to_vec_pretty(idx).context("serialize index")?;
        encrypt::encrypt(&json, recipient).context("encrypt index")
    }

    pub fn decode_index(
        &self,
        ciphertext: &[u8],
        identity: &age::x25519::Identity,
    ) -> Result<ChatsIndex> {
        let plaintext = encrypt::decrypt(ciphertext, identity).context("decrypt index")?;
        serde_json::from_slice(&plaintext).context("parse index JSON")
    }

    /// Load the index from the primary store, returning empty + None on first
    /// run. The etag is used later for the CAS write that saves the updated
    /// index back.
    pub async fn load_index(
        &self,
        primary: &dyn SnapshotStore,
        identity: &age::x25519::Identity,
    ) -> Result<(ChatsIndex, Option<String>)> {
        let key = self.index_key();
        match primary.head(&key).await? {
            None => Ok((ChatsIndex::empty(), None)),
            Some(_) => {
                let (bytes, etag) = primary
                    .get(&key)
                    .await
                    .with_context(|| format!("get {key}"))?;
                let idx = self.decode_index(&bytes, identity)?;
                Ok((idx, Some(etag)))
            }
        }
    }

    /// CAS write of the index + best-effort mirror fan-out.
    pub async fn save_index(
        &self,
        ctx: &WorkloadCtx<'_>,
        idx: &ChatsIndex,
        prev_etag: Option<String>,
    ) -> Result<()> {
        let mut to_save = idx.clone();
        to_save.updated_at = Utc::now();
        let bytes = self.encode_index(&to_save, ctx.recipient)?;
        let key = self.index_key();
        ctx.primary
            .put_if_unmodified(&key, bytes.clone(), prev_etag.as_deref())
            .await
            .with_context(|| format!("CAS update of {key}"))?;
        stores::fanout(ctx.mirrors, &key, bytes).await;
        Ok(())
    }

    /// Persist one conversation's body (zstd + age) on the primary store and
    /// fan it out to mirrors. Returns the index entry the caller should record.
    pub async fn store_conversation(
        &self,
        ctx: &WorkloadCtx<'_>,
        id: &str,
        title: Option<String>,
        update_time: Option<f64>,
        body: &serde_json::Value,
    ) -> Result<ChatsIndexEntry> {
        let ciphertext = self.encode_conversation(body, ctx.recipient)?;
        let key = self.conv_key(id);
        let sha = sha256_hex(&ciphertext);
        let bytes_len = ciphertext.len() as u64;
        ctx.primary
            .put(&key, ciphertext.clone())
            .await
            .with_context(|| format!("put {key}"))?;
        stores::fanout(ctx.mirrors, &key, ciphertext).await;
        Ok(ChatsIndexEntry {
            update_time,
            title,
            object_key: key,
            sha256: sha,
            bytes: bytes_len,
            stored_at: Utc::now(),
        })
    }
}

#[async_trait]
impl Workload for ChatgptChatsWorkload {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    async fn run(&self, ctx: &WorkloadCtx<'_>) -> Result<()> {
        let (mut index, prev_etag) = self.load_index(ctx.primary, ctx.identity).await?;
        info!(
            workload = %self.cfg.name,
            known = index.entries.len(),
            "loaded chats index"
        );

        let client = ChatsApiClient::new(ctx.http.clone(), self.cfg.clone()).await?;

        // ── Phase 1: pagination with early-stop ──────────────────────────────
        let to_fetch = self.collect_outdated(&client, &index).await?;
        if to_fetch.is_empty() {
            info!(workload = %self.cfg.name, "no new or updated conversations");
            return Ok(());
        }
        info!(
            workload = %self.cfg.name,
            count = to_fetch.len(),
            "fetching conversation bodies"
        );

        // ── Phase 2: fetch + store, with per-batch cooldowns ─────────────────
        let mut failed: Vec<ConversationSummary> = Vec::new();
        let batch_size = self.cfg.detail_batch_size.max(1) as usize;
        for (i, chunk) in to_fetch.chunks(batch_size).enumerate() {
            if i > 0 {
                let pause = Duration::from_millis(self.cfg.detail_batch_cooldown_ms);
                info!(
                    workload = %self.cfg.name,
                    secs = pause.as_secs(),
                    "batch cooldown"
                );
                tokio::time::sleep(pause).await;
            }
            for summary in chunk {
                tokio::time::sleep(Duration::from_millis(self.cfg.detail_delay_ms)).await;
                match client.get_raw(&summary.id).await {
                    Ok(body) => {
                        let entry = self
                            .store_conversation(
                                ctx,
                                &summary.id,
                                summary.title.clone(),
                                summary.update_time,
                                &body,
                            )
                            .await?;
                        index.entries.insert(summary.id.clone(), entry);
                    }
                    Err(FetchError::Inaccessible(msg)) => {
                        warn!(
                            workload = %self.cfg.name,
                            id = %summary.id,
                            error = %msg,
                            "skipping inaccessible conversation"
                        );
                    }
                    Err(FetchError::Transient(msg)) => {
                        warn!(
                            workload = %self.cfg.name,
                            id = %summary.id,
                            error = %msg,
                            "transient failure, will retry in sweep"
                        );
                        failed.push(summary.clone());
                    }
                    Err(FetchError::Fatal(e)) => return Err(e),
                }
            }
        }

        // ── Phase 3: single retry sweep ──────────────────────────────────────
        if !failed.is_empty() {
            let pause = Duration::from_millis(self.cfg.retry_sweep_cooldown_ms);
            info!(
                workload = %self.cfg.name,
                failed = failed.len(),
                secs = pause.as_secs(),
                "retry sweep cooldown"
            );
            tokio::time::sleep(pause).await;
            for summary in &failed {
                tokio::time::sleep(Duration::from_millis(self.cfg.detail_delay_ms)).await;
                match client.get_raw(&summary.id).await {
                    Ok(body) => {
                        let entry = self
                            .store_conversation(
                                ctx,
                                &summary.id,
                                summary.title.clone(),
                                summary.update_time,
                                &body,
                            )
                            .await?;
                        index.entries.insert(summary.id.clone(), entry);
                    }
                    Err(e) => {
                        warn!(
                            workload = %self.cfg.name,
                            id = %summary.id,
                            error = %e,
                            "retry sweep failed; leaving conversation for next run"
                        );
                    }
                }
            }
        }

        // ── Phase 4: save index ──────────────────────────────────────────────
        self.save_index(ctx, &index, prev_etag).await?;
        info!(
            workload = %self.cfg.name,
            total = index.entries.len(),
            "chats workload complete"
        );
        Ok(())
    }
}

impl ChatgptChatsWorkload {
    /// Walk the list endpoint until we've seen `incremental_stop_after_known`
    /// consecutive items that match our index — those represent the boundary
    /// where we've caught up with last run's history.
    async fn collect_outdated(
        &self,
        client: &ChatsApiClient,
        index: &ChatsIndex,
    ) -> Result<Vec<ConversationSummary>> {
        let limit = self.cfg.list_page_limit.max(1);
        let stop_after = self.cfg.incremental_stop_after_known.max(1);
        let mut to_fetch: Vec<ConversationSummary> = Vec::new();
        let mut offset = 0u32;
        let mut consecutive_known = 0u32;
        loop {
            tokio::time::sleep(Duration::from_millis(self.cfg.list_delay_ms)).await;
            let page = client.list(offset, limit).await?;
            if page.items.is_empty() {
                break;
            }
            let returned = page.items.len() as u32;
            for summary in page.items {
                let known = index
                    .entries
                    .get(&summary.id)
                    .map(|e| e.update_time == summary.update_time)
                    .unwrap_or(false);
                if known {
                    consecutive_known += 1;
                    if consecutive_known >= stop_after {
                        info!(
                            workload = %self.cfg.name,
                            stop_after,
                            offset,
                            "incremental stop: caught up with last run"
                        );
                        return Ok(to_fetch);
                    }
                } else {
                    consecutive_known = 0;
                    to_fetch.push(summary);
                }
            }
            // Short final page → end of list.
            if returned < limit {
                break;
            }
            offset += limit;
        }
        Ok(to_fetch)
    }
}

// ── HTTP client ──────────────────────────────────────────────────────────────

/// API errors are classified so the workload can decide:
///   * Inaccessible → skip permanently this run, don't write index for it
///   * Transient    → queue for retry sweep
///   * Fatal        → propagate (auth expired, etc.)
#[derive(Debug)]
enum FetchError {
    Inaccessible(String),
    Transient(String),
    Fatal(eyre::Report),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Inaccessible(m) | FetchError::Transient(m) => f.write_str(m),
            FetchError::Fatal(e) => write!(f, "{e:#}"),
        }
    }
}

struct ChatsApiClient {
    http: reqwest::Client,
    cfg: ChatgptChatsCfg,
    /// Wrapped so a 401 mid-run can refresh transparently without rebuilding
    /// the client. Sequential awaits in the workload mean a plain
    /// `std::sync::Mutex` is enough — no async lock needed.
    token: Mutex<String>,
}

impl ChatsApiClient {
    async fn new(http: reqwest::Client, cfg: ChatgptChatsCfg) -> Result<Self> {
        let token = Self::fetch_session(&http, &cfg).await?;
        info!(
            workload = %cfg.name,
            preview = %&token[..20.min(token.len())],
            "access token acquired"
        );
        Ok(Self {
            http,
            cfg,
            token: Mutex::new(token),
        })
    }

    async fn fetch_session(http: &reqwest::Client, cfg: &ChatgptChatsCfg) -> Result<String> {
        let url = format!("{}{}", cfg.base_url, cfg.session_path);
        let resp = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        if !status.is_success() {
            bail!(
                "{} returned {} — session expired; re-run `repossess seed`",
                url,
                status.as_u16()
            );
        }
        let session: SessionResponse = resp.json().await.context("parse session JSON")?;
        session
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                eyre!(
                    "no accessToken in session response — session may be invalid; \
                     re-run `repossess seed`"
                )
            })
    }

    fn current_token(&self) -> String {
        // Clone the bytes so we drop the guard before any `.await`.
        self.token.lock().expect("token mutex poisoned").clone()
    }

    async fn refresh_token(&self) -> Result<()> {
        let new_tok = Self::fetch_session(&self.http, &self.cfg).await?;
        *self.token.lock().expect("token mutex poisoned") = new_tok;
        Ok(())
    }

    async fn list(&self, offset: u32, limit: u32) -> Result<ConversationListResponse> {
        let url = format!(
            "{}{}?offset={offset}&limit={limit}",
            self.cfg.base_url, self.cfg.list_path
        );
        // For list calls, any error is fatal to the workload's run — flatten
        // GetError into the eyre Report rather than carry the classification.
        let value = self
            .get_json(&url)
            .await
            .map_err(|e| match e {
                GetError::Fatal(r) => r,
                GetError::Transient(m) | GetError::Inaccessible(m) => eyre!("{m}"),
            })?;
        serde_json::from_value(value).with_context(|| format!("deserialize list from {url}"))
    }

    async fn get_raw(&self, id: &str) -> Result<serde_json::Value, FetchError> {
        let path = self.cfg.detail_path_template.replace("{id}", id);
        let url = format!("{}{}", self.cfg.base_url, path);
        match self.get_json(&url).await {
            Ok(v) => Ok(v),
            Err(GetError::Inaccessible(m)) => Err(FetchError::Inaccessible(m)),
            Err(GetError::Transient(m)) => Err(FetchError::Transient(m)),
            Err(GetError::Fatal(e)) => Err(FetchError::Fatal(e)),
        }
    }

    async fn get_json(&self, url: &str) -> std::result::Result<serde_json::Value, GetError> {
        let mut attempt = 0u32;
        let mut refreshed_once = false;
        loop {
            let token = self.current_token();
            let req = self
                .http
                .get(url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Accept", "application/json")
                .header("Accept-Language", "en-US,en;q=0.9")
                .header("Referer", format!("{}/", self.cfg.base_url))
                .header("sec-fetch-dest", "empty")
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-site", "same-origin");
            let resp = req
                .send()
                .await
                .map_err(|e| GetError::Fatal(eyre!("GET {url}: {e}")))?;
            let status = resp.status();

            if status == StatusCode::TOO_MANY_REQUESTS {
                attempt += 1;
                if attempt > self.cfg.max_retries {
                    return Err(GetError::Transient(format!(
                        "GET {url}: 429 after {} retries",
                        self.cfg.max_retries
                    )));
                }
                let backoff = retry_after(&resp)
                    .unwrap_or_else(|| exponential_backoff(attempt, self.cfg.max_backoff_ms));
                warn!(
                    attempt,
                    wait_secs = backoff.as_secs(),
                    url,
                    "429 — backing off"
                );
                tokio::time::sleep(backoff).await;
                continue;
            }

            if status == StatusCode::UNAUTHORIZED {
                if refreshed_once {
                    return Err(GetError::Fatal(eyre!(
                        "GET {url}: 401 after token refresh; re-run `repossess seed`"
                    )));
                }
                refreshed_once = true;
                warn!(url, "401 — refreshing session token");
                self.refresh_token().await.map_err(GetError::Fatal)?;
                continue;
            }

            if status.is_server_error() {
                attempt += 1;
                if attempt > self.cfg.max_retries {
                    return Err(GetError::Transient(format!(
                        "GET {url}: {} after {} retries",
                        status.as_u16(),
                        self.cfg.max_retries
                    )));
                }
                let backoff = exponential_backoff(attempt, self.cfg.max_backoff_ms);
                warn!(
                    attempt,
                    wait_secs = backoff.as_secs(),
                    status = status.as_u16(),
                    "5xx — backing off"
                );
                tokio::time::sleep(backoff).await;
                continue;
            }

            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(GetError::Fatal(eyre!(
                    "GET {url}: status {} body {body}",
                    status.as_u16()
                )));
            }

            let raw = resp
                .text()
                .await
                .map_err(|e| GetError::Fatal(eyre!("read {url}: {e}")))?;
            let body: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| GetError::Fatal(eyre!("parse JSON from {url}: {e}")))?;

            // ChatGPT replies 200 with `{"detail": ...}` for permission errors
            // like project/gizmo chats. Classify those as Inaccessible so we
            // skip them rather than poison the run.
            if let Some(detail) = body.get("detail") {
                let msg = match detail {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Object(_) => {
                        let code = detail
                            .get("code")
                            .and_then(|c| c.as_str())
                            .unwrap_or("api_error");
                        let m = detail.get("message").and_then(|m| m.as_str()).unwrap_or("");
                        format!("{code}: {m}")
                    }
                    other => format!("{other}"),
                };
                if msg.contains("inaccessible") || msg.contains("not_found") {
                    return Err(GetError::Inaccessible(msg));
                }
                return Err(GetError::Fatal(eyre!("API error from {url}: {msg}")));
            }

            return Ok(body);
        }
    }
}

enum GetError {
    Inaccessible(String),
    Transient(String),
    Fatal(eyre::Report),
}

fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn exponential_backoff(attempt: u32, cap_ms: u64) -> Duration {
    // 30s × 2^attempt, capped. Mirrors the JS exporter's intuition without
    // pulling in a jitter dependency.
    let base = 30_000u64.saturating_mul(2u64.saturating_pow(attempt.min(5)));
    Duration::from_millis(base.min(cap_ms))
}
