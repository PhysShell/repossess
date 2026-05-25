use eyre::{bail, eyre, Context, Result};
use futures::stream::{self, StreamExt};
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
///
/// Uploads run with `concurrency` in flight. There's no API rate limit to
/// respect here (the data is already on disk), so the only ceiling is what
/// the object store will accept — 8 is a safe default for R2/S3, bump it
/// if your store/network has headroom.
pub async fn run(cfg: &Config, from: &Path, concurrency: usize, dry_run: bool) -> Result<()> {
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

    if concurrency == 0 {
        bail!("--concurrency must be >= 1");
    }

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

    // ── Phase 1: scan + classify all conversations ─────────────────────────
    let mut pending: Vec<PendingItem> = Vec::new();
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
            // already at-or-after the archive — skip without re-encoding.
            if let Some(existing) = index.entries.get(&id) {
                if existing.update_time == update_time {
                    skipped += 1;
                    continue;
                }
            }
            pending.push(PendingItem {
                id,
                title,
                update_time,
                value,
            });
        }
    }
    tracing::info!(
        to_upload = pending.len(),
        skipped,
        malformed,
        concurrency,
        dry_run,
        "scan complete"
    );

    if dry_run {
        println!(
            "dry run: would upload {} new/updated, skip {skipped} already-current, {malformed} malformed",
            pending.len()
        );
        return Ok(());
    }

    // ── Phase 2: parallel upload with bounded in-flight ────────────────────
    //
    // A single failed upload shouldn't abort a 2k-item bootstrap — log it,
    // count it, and let the run finish. The final index reflects what made
    // it through, so re-running the import will retry only the failures
    // (they're not in the index → not skipped by the update_time check).
    let workload_ref = &workload;
    let ctx_ref = &ctx;
    let upload_stream = stream::iter(pending.into_iter().map(move |item| async move {
        let result = workload_ref
            .store_conversation(
                ctx_ref,
                &item.id,
                item.title.clone(),
                item.update_time,
                &item.value,
            )
            .await
            .with_context(|| format!("store {}", item.id));
        (item.id, result)
    }))
    .buffer_unordered(concurrency);

    let mut imported = 0usize;
    let mut failed = 0usize;
    futures::pin_mut!(upload_stream);
    while let Some((id, result)) = upload_stream.next().await {
        match result {
            Ok(entry) => {
                index.entries.insert(id, entry);
                imported += 1;
                if imported.is_multiple_of(100) {
                    tracing::info!(imported, failed, skipped, "import progress");
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(id = %id, error = %e, "upload failed");
            }
        }
    }

    // ── Phase 3: save what we have, even on partial failure ────────────────
    workload.save_index(&ctx, &index, prev_etag).await?;

    println!(
        "imported {imported} new/updated, skipped {skipped} already-current, \
         {failed} failed, {malformed} malformed; index size now {}",
        index.entries.len()
    );
    if failed > 0 {
        bail!("{failed} conversation(s) failed to upload; re-run to retry");
    }
    Ok(())
}

struct PendingItem {
    id: String,
    title: Option<String>,
    update_time: Option<f64>,
    value: serde_json::Value,
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
