//! Workload-level behavior tests for `ChatgptChatsWorkload`.
//!
//! What's real here, and what isn't, so the test failures actually mean
//! something:
//!
//! * **HTTP is real.** A `wiremock::MockServer` listens on a real port; the
//!   workload's `reqwest::Client` makes real GET requests, with real
//!   Authorization headers, real JSON parsing, real status-code branching.
//!   We control the responses, but the protocol is genuine.
//!
//! * **Crypto is real.** Each test generates a fresh age x25519 keypair and
//!   round-trips per-conversation bodies + the index through the same
//!   `encrypt::encrypt`/`decrypt` path the production workload uses.
//!
//! * **The store is in-memory** but implements `SnapshotStore`'s CAS
//!   contract honestly: if the workload passes the wrong `expected_etag`
//!   to `put_if_unmodified`, the store rejects it the same way R2 would.
//!   That makes the CAS semantics objectively verifiable, but it does NOT
//!   model real-R2 quirks: cross-process races, eventual consistency
//!   between read-after-write replicas, or network partitions. Those still
//!   need integration coverage against a real backend (MinIO in
//!   `scripts/smoke.sh`).
//!
//! * **Rate-limit delays are zeroed** in `make_cfg` so the suite runs in
//!   milliseconds. The retry/backoff *branches* are still exercised — only
//!   the wall-clock waits are short-circuited.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use eyre::{bail, Result};
use serde_json::json;
use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use repossess::config::ChatgptChatsCfg;
use repossess::stores::{ObjectMeta, PutResult, SnapshotStore};
use repossess::workload::chatgpt_chats::{ChatgptChatsWorkload, ChatsIndex, ChatsIndexEntry};
use repossess::workload::{Workload, WorkloadCtx};

// ── In-memory SnapshotStore with faithful CAS semantics ─────────────────────

struct InMemoryStore {
    name: String,
    inner: Mutex<HashMap<String, (Bytes, u64)>>,
    counter: Mutex<u64>,
}

impl InMemoryStore {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            inner: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
        }
    }

    fn next_etag(&self) -> u64 {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        *c
    }
}

#[async_trait]
impl SnapshotStore for InMemoryStore {
    fn name(&self) -> &str {
        &self.name
    }

    async fn put(&self, key: &str, body: Bytes) -> Result<PutResult> {
        let etag = self.next_etag();
        self.inner.lock().unwrap().insert(key.into(), (body, etag));
        Ok(PutResult {
            etag: etag.to_string(),
        })
    }

    async fn put_if_unmodified(
        &self,
        key: &str,
        body: Bytes,
        expected_etag: Option<&str>,
    ) -> Result<PutResult> {
        let mut m = self.inner.lock().unwrap();
        match (m.get(key), expected_etag) {
            (Some(_), None) => bail!("CAS create-only: {key} already exists"),
            (None, Some(e)) => {
                bail!("CAS update-only: {key} does not exist (expected etag {e})")
            }
            (Some((_, cur)), Some(e)) if cur.to_string() != e => {
                bail!("CAS etag mismatch on {key}: have {cur}, expected {e}")
            }
            _ => {}
        }
        let etag = {
            let mut c = self.counter.lock().unwrap();
            *c += 1;
            *c
        };
        m.insert(key.into(), (body, etag));
        Ok(PutResult {
            etag: etag.to_string(),
        })
    }

    async fn get(&self, key: &str) -> Result<(Bytes, String)> {
        let m = self.inner.lock().unwrap();
        m.get(key)
            .map(|(b, e)| (b.clone(), e.to_string()))
            .ok_or_else(|| eyre::eyre!("not found: {key}"))
    }

    async fn head(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(key)
            .map(|(_, e)| e.to_string()))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, (b, e))| ObjectMeta {
                key: k.clone(),
                etag: e.to_string(),
                size: b.len() as u64,
            })
            .collect())
    }

    async fn delete_if_match(&self, key: &str, etag: &str) -> Result<()> {
        let mut m = self.inner.lock().unwrap();
        match m.get(key) {
            Some((_, cur)) if cur.to_string() == etag => {
                m.remove(key);
                Ok(())
            }
            Some((_, cur)) => {
                bail!("delete etag mismatch on {key}: have {cur}, expected {etag}")
            }
            None => Ok(()),
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn make_cfg(base_url: String) -> ChatgptChatsCfg {
    ChatgptChatsCfg {
        name: "test-chats".into(),
        prefix: "chatgpt/".into(),
        base_url,
        session_path: "/api/auth/session".into(),
        list_path: "/backend-api/conversations".into(),
        detail_path_template: "/backend-api/conversation/{id}".into(),
        list_page_limit: 28,
        incremental_stop_after_known: 50,
        // All delays zero — keeps the suite in the millisecond range. The
        // retry/backoff *branches* still execute; only wall-clock sleeps do not.
        list_delay_ms: 0,
        detail_delay_ms: 0,
        detail_batch_size: 75,
        detail_batch_cooldown_ms: 0,
        retry_sweep_cooldown_ms: 0,
        max_backoff_ms: 1_000,
        max_retries: 3,
        zstd_level: 1,
    }
}

fn list_response(items: &[(&str, &str, f64)]) -> serde_json::Value {
    json!({
        "items": items
            .iter()
            .map(|(id, title, ut)| {
                json!({"id": id, "title": title, "update_time": ut})
            })
            .collect::<Vec<_>>()
    })
}

fn conversation_body(id: &str, title: &str, update_time: f64) -> serde_json::Value {
    let user_id = format!("{id}-msg-user");
    let asst_id = format!("{id}-msg-asst");
    json!({
        "conversation_id": id,
        "title": title,
        "create_time": update_time - 60.0,
        "update_time": update_time,
        "mapping": {
            user_id.clone(): {
                "id": user_id.clone(),
                "parent": null,
                "children": [asst_id.clone()],
                "message": {
                    "id": user_id.clone(),
                    "author": {"role": "user"},
                    "create_time": update_time - 30.0,
                    "content": {"content_type": "text", "parts": ["hello"]},
                    "status": "finished_successfully"
                }
            },
            asst_id.clone(): {
                "id": asst_id.clone(),
                "parent": user_id.clone(),
                "children": [],
                "message": {
                    "id": asst_id.clone(),
                    "author": {"role": "assistant"},
                    "create_time": update_time - 10.0,
                    "content": {"content_type": "text", "parts": ["hi there"]},
                    "status": "finished_successfully"
                }
            }
        },
        "current_node": asst_id
    })
}

async fn mount_session(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/api/auth/session"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"accessToken": token})),
        )
        .mount(server)
        .await;
}

async fn mount_list(server: &MockServer, items: &[(&str, &str, f64)]) {
    Mock::given(method("GET"))
        .and(path("/backend-api/conversations"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list_response(items)))
        .mount(server)
        .await;
}

async fn mount_detail(server: &MockServer, id: &str, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/backend-api/conversation/{id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn count_calls_to(server: &MockServer, path_prefix: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path().starts_with(path_prefix))
        .count()
}

struct TestSetup {
    server: MockServer,
    store: InMemoryStore,
    identity: age::x25519::Identity,
    recipient: age::x25519::Recipient,
}

async fn setup() -> TestSetup {
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    TestSetup {
        server: MockServer::start().await,
        store: InMemoryStore::new("primary"),
        identity,
        recipient,
    }
}

/// Run a workload against a fresh `WorkloadCtx`. Wraps the lifetime juggling
/// so each test reads top-to-bottom.
async fn run_workload(setup: &TestSetup, workload: &ChatgptChatsWorkload) -> Result<()> {
    let http = reqwest::Client::new();
    let mirrors: Vec<Box<dyn SnapshotStore>> = Vec::new();
    let ctx = WorkloadCtx {
        http: &http,
        primary: &setup.store,
        mirrors: &mirrors,
        recipient: &setup.recipient,
        identity: &setup.identity,
    };
    workload.run(&ctx).await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn first_run_crawls_and_stores_all_conversations() {
    let setup = setup().await;
    mount_session(&setup.server, "token-A").await;
    mount_list(
        &setup.server,
        &[("conv-1", "First", 1000.0), ("conv-2", "Second", 2000.0)],
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-1",
        conversation_body("conv-1", "First", 1000.0),
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-2",
        conversation_body("conv-2", "Second", 2000.0),
    )
    .await;

    let workload = ChatgptChatsWorkload::new(make_cfg(setup.server.uri()));
    run_workload(&setup, &workload).await.expect("workload run");

    let (idx, _) = workload
        .load_index(&setup.store, &setup.identity)
        .await
        .expect("load index");
    assert_eq!(idx.entries.len(), 2, "both conversations indexed");
    assert!(idx.entries.contains_key("conv-1"));
    assert!(idx.entries.contains_key("conv-2"));

    // Bodies round-trip through encryption + compression and contain the
    // title we sent — proves the full pipeline, not just metadata bookkeeping.
    let (bytes, _) = setup
        .store
        .get("chatgpt/conv/conv-1.json.zst.age")
        .await
        .expect("get conv-1 body");
    let decoded = workload
        .decode_conversation(&bytes, &setup.identity)
        .expect("decode conv-1");
    assert_eq!(decoded["title"], "First");
    assert_eq!(decoded["conversation_id"], "conv-1");
}

#[tokio::test]
async fn second_run_with_same_state_does_no_detail_fetches() {
    let setup = setup().await;
    mount_session(&setup.server, "token-A").await;
    mount_list(
        &setup.server,
        &[("conv-1", "First", 1000.0), ("conv-2", "Second", 2000.0)],
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-1",
        conversation_body("conv-1", "First", 1000.0),
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-2",
        conversation_body("conv-2", "Second", 2000.0),
    )
    .await;

    let workload = ChatgptChatsWorkload::new(make_cfg(setup.server.uri()));
    run_workload(&setup, &workload).await.expect("first run");

    let detail_calls_after_first = count_calls_to(&setup.server, "/backend-api/conversation/").await;
    assert_eq!(detail_calls_after_first, 2, "first run fetches both bodies");

    run_workload(&setup, &workload).await.expect("second run");

    let detail_calls_after_second =
        count_calls_to(&setup.server, "/backend-api/conversation/").await;
    assert_eq!(
        detail_calls_after_second, 2,
        "second run must NOT re-fetch any detail bodies; saw {detail_calls_after_second} total"
    );
}

#[tokio::test]
async fn update_time_change_triggers_targeted_refetch() {
    let setup = setup().await;
    mount_session(&setup.server, "token-A").await;

    // Pre-seed the index: conv-1 known at update_time=1000, conv-2 at 500.
    // We only need update_time accurate for the change-detection check; the
    // other fields just need to deserialize.
    let mut seed = ChatsIndex::empty();
    seed.entries.insert(
        "conv-1".into(),
        ChatsIndexEntry {
            update_time: Some(1000.0),
            title: Some("First".into()),
            object_key: "chatgpt/conv/conv-1.json.zst.age".into(),
            sha256: "stub-sha-1".into(),
            bytes: 0,
            stored_at: chrono::Utc::now(),
        },
    );
    seed.entries.insert(
        "conv-2".into(),
        ChatsIndexEntry {
            update_time: Some(500.0),
            title: Some("Second".into()),
            object_key: "chatgpt/conv/conv-2.json.zst.age".into(),
            sha256: "stub-sha-2".into(),
            bytes: 0,
            stored_at: chrono::Utc::now(),
        },
    );
    let workload = ChatgptChatsWorkload::new(make_cfg(setup.server.uri()));
    let seed_bytes = workload
        .encode_index(&seed, &setup.recipient)
        .expect("encode seed index");
    setup
        .store
        .put("chatgpt/index.json.age", seed_bytes)
        .await
        .expect("put seed index");

    // List reports conv-1 bumped to 2000 (changed) and conv-2 still at 500
    // (unchanged). Only conv-1's detail endpoint should be hit.
    mount_list(
        &setup.server,
        &[("conv-1", "First (updated)", 2000.0), ("conv-2", "Second", 500.0)],
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-1",
        conversation_body("conv-1", "First (updated)", 2000.0),
    )
    .await;

    run_workload(&setup, &workload).await.expect("workload run");

    let calls_to_conv1 = count_calls_to(&setup.server, "/backend-api/conversation/conv-1").await;
    let calls_to_conv2 = count_calls_to(&setup.server, "/backend-api/conversation/conv-2").await;
    assert_eq!(calls_to_conv1, 1, "changed conversation must be refetched");
    assert_eq!(
        calls_to_conv2, 0,
        "unchanged conversation must NOT be refetched; saw {calls_to_conv2} calls"
    );

    let (idx, _) = workload
        .load_index(&setup.store, &setup.identity)
        .await
        .unwrap();
    assert_eq!(
        idx.entries.get("conv-1").unwrap().update_time,
        Some(2000.0),
        "index reflects new update_time"
    );
    assert_eq!(
        idx.entries.get("conv-2").unwrap().update_time,
        Some(500.0),
        "untouched entry preserved exactly"
    );
}

#[tokio::test]
async fn unauthorized_triggers_session_refresh_and_retry() {
    let setup = setup().await;

    // Two session mocks: each call returns a (possibly different) valid
    // token. The workload should hit /api/auth/session twice: once at
    // startup, once after the 401.
    mount_session(&setup.server, "token-fresh").await;

    mount_list(&setup.server, &[("conv-1", "First", 1000.0)]).await;

    // Detail endpoint: first call returns 401, second returns 200.
    // wiremock's up_to_n_times caps the first mock at one match; the second
    // mock then catches the retry.
    Mock::given(method("GET"))
        .and(path("/backend-api/conversation/conv-1"))
        .respond_with(ResponseTemplate::new(401))
        .up_to_n_times(1)
        .mount(&setup.server)
        .await;
    Mock::given(method("GET"))
        .and(path("/backend-api/conversation/conv-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(conversation_body("conv-1", "First", 1000.0)),
        )
        .mount(&setup.server)
        .await;

    let workload = ChatgptChatsWorkload::new(make_cfg(setup.server.uri()));
    run_workload(&setup, &workload).await.expect("workload run");

    let session_calls = count_calls_to(&setup.server, "/api/auth/session").await;
    assert_eq!(
        session_calls, 2,
        "expected one initial + one refresh session call, got {session_calls}"
    );
    let detail_calls = count_calls_to(&setup.server, "/backend-api/conversation/conv-1").await;
    assert_eq!(
        detail_calls, 2,
        "expected 401 + retry on detail endpoint, got {detail_calls}"
    );

    // And the conversation actually landed in the index — refresh recovered.
    let (idx, _) = workload
        .load_index(&setup.store, &setup.identity)
        .await
        .unwrap();
    assert!(idx.entries.contains_key("conv-1"));
}

#[tokio::test]
async fn inaccessible_conversation_is_skipped_not_failed() {
    let setup = setup().await;
    mount_session(&setup.server, "token-A").await;
    mount_list(
        &setup.server,
        &[("conv-good", "Good", 1000.0), ("conv-bad", "Bad", 2000.0)],
    )
    .await;
    mount_detail(
        &setup.server,
        "conv-good",
        conversation_body("conv-good", "Good", 1000.0),
    )
    .await;
    // ChatGPT returns 200 with a `{"detail": {...}}` body for permission
    // errors on project/gizmo chats — the workload must classify these as
    // skippable, not fatal.
    Mock::given(method("GET"))
        .and(path_regex(r"^/backend-api/conversation/conv-bad$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": {
                "code": "conversation_inaccessible",
                "message": "Not accessible via this endpoint"
            }
        })))
        .mount(&setup.server)
        .await;

    let workload = ChatgptChatsWorkload::new(make_cfg(setup.server.uri()));
    run_workload(&setup, &workload)
        .await
        .expect("workload must NOT bail on inaccessible conversation");

    let (idx, _) = workload
        .load_index(&setup.store, &setup.identity)
        .await
        .unwrap();
    assert!(idx.entries.contains_key("conv-good"), "good conv stored");
    assert!(
        !idx.entries.contains_key("conv-bad"),
        "inaccessible conv must NOT be in the index"
    );
    // And no body file got created for the bad one.
    assert!(
        setup
            .store
            .head("chatgpt/conv/conv-bad.json.zst.age")
            .await
            .unwrap()
            .is_none(),
        "no encrypted body file for the inaccessible conversation"
    );
}
