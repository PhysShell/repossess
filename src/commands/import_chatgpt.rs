use eyre::{bail, eyre, Context, Result};
use std::path::{Path, PathBuf};

use crate::config::{Config, WorkloadCfg};
use crate::crypto::encrypt;
use crate::env;
use crate::secrets::AgeIdentity;
use crate::stores::{self, SnapshotStore};
use crate::workload::chatgpt_chats::ChatgptChatsWorkload;
use crate::workload::WorkloadCtx;

/// Bootstrap the chats workload from an official ChatGPT data export.
///
/// The export ships as a directory of `conversations-NNN.json` batches, each
/// a top-level JSON array of conversation objects (same shape as the API's
/// detail endpoint, with a few extra fields preserved as-is). We walk those
/// files sequentially, encode each conversation, write it through the same
/// store path the daily workload uses, and emit a single CAS-protected index
/// at the end.
pub async fn run(cfg: &Config, from: &Path, dry_run: bool) -> Result<()> {
    let workload_cfg = cfg
        .workloads
        .iter()
        .map(|w| match w {
            WorkloadCfg::ChatgptChats(c) => c.clone(),
        })
        .next()
        .ok_or_else(|| {
            eyre!(
                "no [[workloads]] entry of kind = \"chatgpt_chats\" found in config; \
                 add one before importing"
            )
        })?;

    let identity = AgeIdentity::take_from_env(env::AGE_IDENTITY)?.parse()?;
    let recipient = encrypt::read_recipient(&cfg.crypto.recipient_file)?;

    let primary = stores::build_store(cfg.primary()).await?;
    let mut mirrors: Vec<Box<dyn SnapshotStore>> = Vec::new();
    for mirror_cfg in cfg.mirrors() {
        match stores::build_store(mirror_cfg).await {
            Ok(s) => mirrors.push(s),
            Err(e) => tracing::warn!(
                store = mirror_cfg.name(),
                error = %e,
                "mirror unavailable, skipping"
            ),
        }
    }

    let workload = ChatgptChatsWorkload::new(workload_cfg);
    let http = reqwest::Client::new(); // not used by import — placeholder for ctx
    let ctx = WorkloadCtx {
        http: &http,
        primary: &*primary,
        mirrors: &mirrors,
        recipient: &recipient,
        identity: &identity,
    };

    let files = list_archive_files(from)?;
    if files.is_empty() {
        bail!(
            "no conversations-*.json files in {} — point --from at the unpacked export dir",
            from.display()
        );
    }
    tracing::info!(files = files.len(), dir = %from.display(), "found archive files");

    let (mut index, prev_etag) = workload.load_index(ctx.primary, ctx.identity).await?;
    tracing::info!(known = index.entries.len(), "loaded existing chats index");

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut malformed = 0usize;

    for path in files {
        tracing::info!(file = %path.display(), "reading");
        let raw = std::fs::read(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let batch: Vec<serde_json::Value> = serde_json::from_slice(&raw).with_context(|| {
            format!(
                "parse {} as JSON array — official exports ship one array per file",
                path.display()
            )
        })?;
        tracing::info!(file = %path.display(), count = batch.len(), "parsed");

        for value in batch {
            let Some(id) = value
                .get("id")
                .or_else(|| value.get("conversation_id"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
            else {
                malformed += 1;
                tracing::warn!("conversation missing id/conversation_id; skipping");
                continue;
            };

            let title = value
                .get("title")
                .and_then(|t| t.as_str())
                .map(str::to_string);
            let update_time = value.get("update_time").and_then(|t| t.as_f64());

            // If our index already has the same update_time, the body is
            // already at-or-after the archive — don't bother re-encoding.
            if let Some(existing) = index.entries.get(&id) {
                if existing.update_time == update_time {
                    skipped += 1;
                    continue;
                }
            }

            if dry_run {
                imported += 1;
                continue;
            }

            let entry = workload
                .store_conversation(&ctx, &id, title, update_time, &value)
                .await
                .with_context(|| format!("store {id}"))?;
            index.entries.insert(id, entry);
            imported += 1;

            if imported.is_multiple_of(100) {
                tracing::info!(imported, skipped, "import progress");
            }
        }
    }

    tracing::info!(imported, skipped, malformed, "import done");

    if dry_run {
        tracing::info!("dry run: skipping index write");
        return Ok(());
    }
    workload.save_index(&ctx, &index, prev_etag).await?;
    println!(
        "imported {imported} new/updated, skipped {skipped} already-current, {malformed} malformed; index size now {}",
        index.entries.len()
    );
    Ok(())
}

fn list_archive_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("conversations") && name.ends_with(".json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}
