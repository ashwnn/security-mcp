use chrono::{Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::{CacheRecord, Database};

#[derive(Clone)]
pub struct CacheStore {
    db: Database,
    enabled: bool,
}

impl CacheStore {
    pub fn new(db: Database, enabled: bool) -> Self {
        Self { db, enabled }
    }

    pub async fn get(
        &self,
        module_id: &str,
        target: &str,
        params: &impl Serialize,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        if !self.enabled {
            return Ok(None);
        }
        let key = cache_key(module_id, target, params)?;
        let hit = self.db.cache_get(&key).await?;
        Ok(hit.map(|r| r.value))
    }

    pub async fn set(
        &self,
        module_id: &str,
        target: &str,
        params: &impl Serialize,
        value: serde_json::Value,
        ttl_seconds: i64,
    ) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let key = cache_key(module_id, target, params)?;
        self.db
            .cache_set(CacheRecord {
                key,
                module_id: module_id.to_string(),
                target: target.to_string(),
                value,
                created_at: Utc::now(),
                expires_at: Utc::now() + Duration::seconds(ttl_seconds),
            })
            .await
    }
}

fn cache_key(module_id: &str, target: &str, params: &impl Serialize) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(module_id.as_bytes());
    hasher.update(b"|");
    hasher.update(target.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(serde_json::to_vec(params)?);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn key_includes_params() {
        let db = Database::connect("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");
        let cache = CacheStore::new(db, true);

        cache
            .set(
                "mod",
                "EXAMPLE.COM",
                &serde_json::json!({"a":1}),
                serde_json::json!({"ok": true}),
                30,
            )
            .await
            .expect("set");

        let miss = cache
            .get("mod", "example.com", &serde_json::json!({"a":2}))
            .await
            .expect("get");
        assert!(miss.is_none());
    }
}
