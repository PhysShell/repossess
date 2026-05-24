use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LATEST_KEY: &str = "latest.json";
pub const LOCK_KEY: &str = "lock.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LatestPointer {
    pub version: String,
    pub object: String,
    pub object_sha256: String,
    pub signature_object: String,
    pub created_at: DateTime<Utc>,
    pub format: SnapshotFormat,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SnapshotFormat {
    /// Playwright-compatible storage_state.json (cookies + origins).
    StorageStateV1,
    /// Full Chromium user_data_dir tarball.
    UserDataDirV1,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_pointer(ts: DateTime<Utc>) -> LatestPointer {
        LatestPointer {
            version: "v1".into(),
            object: "snapshots/test.tar.zst.age".into(),
            object_sha256: sha256_hex(b"payload"),
            signature_object: "snapshots/test.sig".into(),
            created_at: ts,
            format: SnapshotFormat::StorageStateV1,
        }
    }

    #[test]
    fn sha256_hex_changes_with_input() {
        assert_eq!(sha256_hex(b"x"), sha256_hex(b"x"));
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    #[test]
    fn verify_digest_ok() {
        let data = b"hello world";
        assert!(verify_digest(&sha256_hex(data), data).is_ok());
    }

    #[test]
    fn verify_digest_mismatch_errors() {
        let data = b"hello world";
        let err = verify_digest(&sha256_hex(data), b"tampered").unwrap_err();
        assert!(err.to_string().contains("digest mismatch"), "{err}");
    }

    #[test]
    fn monotonic_no_prev_always_ok() {
        assert!(ensure_monotonic(None, &make_pointer(Utc::now())).is_ok());
    }

    #[test]
    fn monotonic_strictly_newer_ok() {
        let t1 = Utc::now();
        let t2 = t1 + chrono::Duration::seconds(1);
        assert!(ensure_monotonic(Some(&make_pointer(t1)), &make_pointer(t2)).is_ok());
    }

    #[test]
    fn monotonic_same_timestamp_rejected() {
        let t = Utc::now();
        assert!(ensure_monotonic(Some(&make_pointer(t)), &make_pointer(t)).is_err());
    }

    #[test]
    fn monotonic_older_timestamp_rejected() {
        let t1 = Utc::now();
        let t2 = t1 - chrono::Duration::seconds(1);
        let err = ensure_monotonic(Some(&make_pointer(t1)), &make_pointer(t2)).unwrap_err();
        assert!(err.to_string().contains("rollback"), "{err}");
    }
}

/// Verify a freshly-fetched snapshot matches the pointer's recorded digest.
pub fn verify_digest(expected_hex: &str, actual_bytes: &[u8]) -> Result<()> {
    let actual = sha256_hex(actual_bytes);
    ensure!(
        actual == expected_hex,
        "snapshot digest mismatch: expected {expected_hex}, got {actual}"
    );
    Ok(())
}

/// Reject pointer rollback: a new pointer must be strictly newer than the previous.
pub fn ensure_monotonic(prev: Option<&LatestPointer>, next: &LatestPointer) -> Result<()> {
    if let Some(p) = prev {
        ensure!(
            next.created_at > p.created_at,
            "pointer rollback detected: prev created_at = {}, next created_at = {}",
            p.created_at,
            next.created_at
        );
    }
    Ok(())
}
