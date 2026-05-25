//! Archive↔API parity check for the ChatGPT chats workload.
//!
//! The fear: if our `mapping` walk or markdown rendering diverges between
//! the official export format and the live API response for the same chat,
//! we silently lose half a conversation on every daily run. This test
//! exercises both inputs through the same code paths and asserts byte-level
//! equivalence on the things that matter.
//!
//! Fixtures live in `tests/fixtures/chatgpt/` and are **not committed** (see
//! `.gitignore`) — they contain real conversation content. Drop two files
//! locally:
//!
//!   tests/fixtures/chatgpt/archive_sample.json   (object or 1-element array
//!                                                  from an official export)
//!   tests/fixtures/chatgpt/api_sample.json       (bare object from the API
//!                                                  detail endpoint, same id)
//!
//! Run with: `cargo test --test chatgpt_parity -- --ignored --nocapture`

use std::path::PathBuf;

use repossess::workload::chatgpt::{to_markdown, ConversationDetail, MappingNode};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("chatgpt")
}

/// Load a fixture and normalize it to a bare conversation object suitable
/// for deserializing into `ConversationDetail`.
///
/// Two shapes are accepted because both occur in the wild:
///   * `{...}`   — what the API detail endpoint returns
///   * `[{...}]` — what the official export emits (a 1-element batch is a
///     common slice produced by hand from a larger `conversations-NNN.json`)
///
/// Then the archive's known quirk is fixed: the export records BOTH
/// `id` and `conversation_id` at the root, and `ConversationDetail`'s
/// `#[serde(alias = "conversation_id")]` on `id` makes serde treat that
/// pair as a duplicate field. Drop `conversation_id` if `id` is present;
/// promote `conversation_id` to `id` if only the API form is there.
fn load_conversation(name: &str) -> serde_json::Value {
    let path = fixtures_dir().join(name);
    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|e| panic!("parse JSON {}: {e}", path.display()));

    let mut value = match value {
        serde_json::Value::Array(mut a) => {
            assert_eq!(
                a.len(),
                1,
                "{name}: expected a bare object or a 1-element array; got {} elements. \
                 Slice down to the conversation that matches the other fixture's id.",
                a.len()
            );
            a.remove(0)
        }
        other => other,
    };

    if let serde_json::Value::Object(map) = &mut value {
        match (map.contains_key("id"), map.remove("conversation_id")) {
            // Both keys present → drop conversation_id (the duplicate that
            // confuses serde) and keep id.
            (true, Some(_)) => {}
            // Only conversation_id present → rename it to id.
            (false, Some(cid)) => {
                map.insert("id".into(), cid);
            }
            // Only id, or neither → nothing to do.
            _ => {}
        }
    }
    value
}

fn parse(value: serde_json::Value) -> ConversationDetail {
    serde_json::from_value(value).expect("deserialize ConversationDetail")
}

fn normalize_text(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_conversation_text(detail: &ConversationDetail) -> Vec<(String, String)> {
    let (Some(mapping), Some(current)) = (&detail.mapping, &detail.current_node) else {
        return Vec::new();
    };
    let mut path: Vec<&MappingNode> = Vec::new();
    let mut id = current.as_str();
    while let Some(node) = mapping.get(id) {
        path.push(node);
        match &node.parent {
            Some(p) => id = p.as_str(),
            None => break,
        }
    }
    path.reverse();

    let mut out = Vec::new();
    for node in path {
        let Some(msg) = &node.message else { continue };
        let text = msg
            .content
            .parts
            .as_deref()
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        if text.trim().is_empty() {
            continue;
        }
        out.push((msg.author.role.clone(), normalize_text(&text)));
    }
    out
}

#[test]
#[ignore = "requires local fixtures in tests/fixtures/chatgpt/; see test source for setup"]
fn archive_and_api_produce_identical_text() {
    let archive = parse(load_conversation("archive_sample.json"));
    let api = parse(load_conversation("api_sample.json"));

    // 1. Same identity.
    assert_eq!(archive.id, api.id, "conversation ids differ — picked wrong samples?");

    // 2. Same head pointer in the DAG.
    assert_eq!(
        archive.current_node, api.current_node,
        "current_node differs — different branches of the same chat?"
    );

    // 3. Same set of mapping node ids.
    let archive_nodes: std::collections::BTreeSet<_> = archive
        .mapping
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let api_nodes: std::collections::BTreeSet<_> = api
        .mapping
        .as_ref()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let only_archive: Vec<_> = archive_nodes.difference(&api_nodes).collect();
    let only_api: Vec<_> = api_nodes.difference(&archive_nodes).collect();
    assert!(
        only_archive.is_empty() && only_api.is_empty(),
        "mapping node ids differ:\n  only in archive: {only_archive:?}\n  only in api:     {only_api:?}"
    );

    // 4. Same (role, normalized-text) sequence from current_node.
    let archive_text = extract_conversation_text(&archive);
    let api_text = extract_conversation_text(&api);
    assert_eq!(
        archive_text.len(),
        api_text.len(),
        "different number of non-empty messages in the active path: archive={}, api={}",
        archive_text.len(),
        api_text.len()
    );
    for (i, (a, b)) in archive_text.iter().zip(api_text.iter()).enumerate() {
        assert_eq!(
            a, b,
            "message #{i} differs between archive and api:\n  archive: {a:?}\n  api:     {b:?}"
        );
    }

    // 5. Same markdown rendering (whitespace-normalized).
    let archive_md = normalize_text(&to_markdown(&archive));
    let api_md = normalize_text(&to_markdown(&api));
    assert_eq!(
        archive_md, api_md,
        "to_markdown() output diverges between archive and api"
    );

    // 6. Metadata divergence is informative, not failing — log only.
    if archive.title != api.title {
        eprintln!(
            "note: titles differ — archive={:?}, api={:?}",
            archive.title, api.title
        );
    }
    if archive.update_time != api.update_time {
        eprintln!(
            "note: update_time differs — archive={:?}, api={:?}",
            archive.update_time, api.update_time
        );
    }
}
