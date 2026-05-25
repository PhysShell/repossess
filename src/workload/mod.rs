use eyre::Result;
use async_trait::async_trait;

use crate::config::WorkloadCfg;
use crate::stores::SnapshotStore;

pub mod chatgpt;
pub mod chatgpt_chats;

/// Shared context handed to every workload when it runs.
///
/// The workload borrows everything: the HTTP client (already carrying the
/// session cookies copied from the restored snapshot), the primary store for
/// CAS reads/writes, the mirrors for best-effort fan-out, and the age keys
/// for per-workload encryption.
pub struct WorkloadCtx<'a> {
    pub http: &'a reqwest::Client,
    pub primary: &'a dyn SnapshotStore,
    pub mirrors: &'a [Box<dyn SnapshotStore>],
    pub recipient: &'a age::x25519::Recipient,
    pub identity: &'a age::x25519::Identity,
}

#[async_trait]
pub trait Workload: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self, ctx: &WorkloadCtx<'_>) -> Result<()>;
}

pub fn build_workload(cfg: &WorkloadCfg) -> Result<Box<dyn Workload>> {
    match cfg {
        WorkloadCfg::ChatgptChats(c) => Ok(Box::new(
            chatgpt_chats::ChatgptChatsWorkload::new(c.clone()),
        )),
    }
}
