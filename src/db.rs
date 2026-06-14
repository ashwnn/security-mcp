use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheRecord {
    pub key: String,
    pub module_id: String,
    pub target: String,
    pub value: serde_json::Value,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub tool: String,
    pub target: String,
    pub target_type: String,
    pub sources_requested: Vec<String>,
    pub sources_used: Vec<String>,
    pub cache_hit: bool,
    pub duration_ms: i64,
    pub status: String,
    pub error_class: Option<String>,
    pub auth_method: String,
}

#[derive(Debug, Clone)]
pub struct OauthCodeRecord {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub scope: String,
    pub state: Option<String>,
    pub resource: String,
    pub subject: String,
    pub expires_at: DateTime<Utc>,
}

impl Database {
    pub async fn connect(path: &str) -> anyhow::Result<Self> {
        let pool = if path.starts_with("sqlite:") {
            SqlitePool::connect(path)
                .await
                .with_context(|| format!("failed to connect sqlite database at {path}"))?
        } else {
            let options = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true);
            SqlitePool::connect_with(options)
                .await
                .with_context(|| format!("failed to connect sqlite database at {path}"))?
        };
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        let statements = [
            "CREATE TABLE IF NOT EXISTS cache_entries (key TEXT PRIMARY KEY, module_id TEXT NOT NULL, target TEXT NOT NULL, value_json TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, request_id TEXT NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL, target_type TEXT NOT NULL, sources_requested TEXT NOT NULL, sources_used TEXT NOT NULL, cache_hit INTEGER NOT NULL, duration_ms INTEGER NOT NULL, status TEXT NOT NULL, error_class TEXT, auth_method TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS oauth_clients (client_id TEXT PRIMARY KEY, client_secret_hash TEXT, redirect_uris_json TEXT NOT NULL, auth_method TEXT NOT NULL, created_at TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS oauth_auth_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL, code_challenge_method TEXT NOT NULL, scope TEXT NOT NULL, state TEXT, resource TEXT, subject TEXT NOT NULL, expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS oauth_access_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, scope TEXT NOT NULL, resource TEXT, subject TEXT NOT NULL, auth_method TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS source_health (source_name TEXT PRIMARY KEY, last_success_at TEXT, last_error_at TEXT, last_error TEXT)",
            "CREATE TABLE IF NOT EXISTS source_usage (source TEXT NOT NULL, window TEXT NOT NULL, request_count INTEGER DEFAULT 0, success_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0, timeout_count INTEGER DEFAULT 0, rate_limit_count INTEGER DEFAULT 0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, reset_estimate TEXT, PRIMARY KEY (source, window))",
        ];

        for statement in statements {
            sqlx::query(statement)
                .execute(&self.pool)
                .await
                .with_context(|| format!("migration failed for statement: {statement}"))?;
        }

        let _ = sqlx::query("ALTER TABLE oauth_auth_codes ADD COLUMN resource TEXT")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("ALTER TABLE oauth_access_tokens ADD COLUMN resource TEXT")
            .execute(&self.pool)
            .await;
        Ok(())
    }

    pub async fn cache_get(&self, key: &str) -> anyhow::Result<Option<CacheRecord>> {
        let row = sqlx::query("SELECT key, module_id, target, value_json, created_at, expires_at FROM cache_entries WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let expires_at: DateTime<Utc> = row.get::<String, _>("expires_at").parse()?;
        if expires_at < Utc::now() {
            self.cache_delete(key).await?;
            return Ok(None);
        }

        Ok(Some(CacheRecord {
            key: row.get("key"),
            module_id: row.get("module_id"),
            target: row.get("target"),
            value: serde_json::from_str(&row.get::<String, _>("value_json"))?,
            created_at: row.get::<String, _>("created_at").parse()?,
            expires_at,
        }))
    }

    pub async fn cache_set(&self, record: CacheRecord) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO cache_entries (key, module_id, target, value_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(record.key)
        .bind(record.module_id)
        .bind(record.target)
        .bind(serde_json::to_string(&record.value)?)
        .bind(record.created_at.to_rfc3339())
        .bind(record.expires_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn cache_delete(&self, key: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM cache_entries WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn cache_clear(&self) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM cache_entries")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn cache_list(&self, limit: i64) -> anyhow::Result<Vec<CacheRecord>> {
        let rows = sqlx::query(
            "SELECT key, module_id, target, value_json, created_at, expires_at FROM cache_entries ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(CacheRecord {
                key: row.get("key"),
                module_id: row.get("module_id"),
                target: row.get("target"),
                value: serde_json::from_str(&row.get::<String, _>("value_json"))?,
                created_at: row.get::<String, _>("created_at").parse()?,
                expires_at: row.get::<String, _>("expires_at").parse()?,
            });
        }
        Ok(out)
    }

    pub async fn audit_insert(&self, event: AuditEvent) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO audit_events (ts, request_id, tool, target, target_type, sources_requested, sources_used, cache_hit, duration_ms, status, error_class, auth_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(Utc::now().to_rfc3339())
            .bind(event.request_id)
            .bind(event.tool)
            .bind(event.target)
            .bind(event.target_type)
            .bind(serde_json::to_string(&event.sources_requested)?)
            .bind(serde_json::to_string(&event.sources_used)?)
            .bind(i64::from(event.cache_hit))
            .bind(event.duration_ms)
            .bind(event.status)
            .bind(event.error_class)
            .bind(event.auth_method)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn audit_list(&self, limit: i64) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT ts, request_id, tool, target, target_type, status, duration_ms, auth_method, error_class FROM audit_events ORDER BY id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(serde_json::json!({
                "ts": row.get::<String, _>("ts"),
                "request_id": row.get::<String, _>("request_id"),
                "tool": row.get::<String, _>("tool"),
                "target": row.get::<String, _>("target"),
                "target_type": row.get::<String, _>("target_type"),
                "status": row.get::<String, _>("status"),
                "duration_ms": row.get::<i64, _>("duration_ms"),
                "auth_method": row.get::<String, _>("auth_method"),
                "error_class": row.get::<Option<String>, _>("error_class"),
            }));
        }
        Ok(out)
    }

    pub async fn oauth_store_client(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
        redirect_uris: &[String],
        auth_method: &str,
    ) -> anyhow::Result<()> {
        let secret_hash = client_secret.map(hash_secret);
        sqlx::query("INSERT OR REPLACE INTO oauth_clients (client_id, client_secret_hash, redirect_uris_json, auth_method, created_at) VALUES (?, ?, ?, ?, ?)")
            .bind(client_id)
            .bind(secret_hash)
            .bind(serde_json::to_string(redirect_uris)?)
            .bind(auth_method)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn oauth_get_client(
        &self,
        client_id: &str,
    ) -> anyhow::Result<Option<(String, Option<String>, Vec<String>, String)>> {
        let row = sqlx::query("SELECT client_id, client_secret_hash, redirect_uris_json, auth_method FROM oauth_clients WHERE client_id = ?")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let redirects: Vec<String> =
            serde_json::from_str(&row.get::<String, _>("redirect_uris_json"))?;
        Ok(Some((
            row.get("client_id"),
            row.get("client_secret_hash"),
            redirects,
            row.get("auth_method"),
        )))
    }

    pub async fn oauth_store_code(&self, record: OauthCodeRecord) -> anyhow::Result<()> {
        let code_hash = hash_secret(&record.code);
        sqlx::query("INSERT INTO oauth_auth_codes (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, scope, state, resource, subject, expires_at, consumed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)")
            .bind(code_hash)
            .bind(record.client_id)
            .bind(record.redirect_uri)
            .bind(record.code_challenge)
            .bind(record.code_challenge_method)
            .bind(record.scope)
            .bind(record.state)
            .bind(record.resource)
            .bind(record.subject)
            .bind(record.expires_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn oauth_get_valid_code(
        &self,
        code: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let code_hash = hash_secret(code);
        let row = sqlx::query("SELECT client_id, redirect_uri, code_challenge, code_challenge_method, scope, state, resource, subject, expires_at, consumed FROM oauth_auth_codes WHERE code_hash = ?")
            .bind(code_hash.clone())
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let consumed: i64 = row.get("consumed");
        let expires_at: DateTime<Utc> = row.get::<String, _>("expires_at").parse()?;
        if consumed != 0 || expires_at < Utc::now() {
            return Ok(None);
        }

        Ok(Some(serde_json::json!({
            "client_id": row.get::<String, _>("client_id"),
            "redirect_uri": row.get::<String, _>("redirect_uri"),
            "code_challenge": row.get::<String, _>("code_challenge"),
            "code_challenge_method": row.get::<String, _>("code_challenge_method"),
            "scope": row.get::<String, _>("scope"),
            "state": row.get::<Option<String>, _>("state"),
            "resource": row.get::<Option<String>, _>("resource"),
            "subject": row.get::<String, _>("subject"),
        })))
    }

    pub async fn oauth_consume_code(&self, code: &str) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE oauth_auth_codes SET consumed = 1 WHERE code_hash = ? AND consumed = 0 AND expires_at >= ?",
        )
        .bind(hash_secret(code))
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn oauth_store_access_token(
        &self,
        token: &str,
        client_id: &str,
        scope: &str,
        resource: &str,
        subject: &str,
        auth_method: &str,
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        let token_hash = hash_secret(token);
        sqlx::query("INSERT INTO oauth_access_tokens (token_hash, client_id, scope, resource, subject, auth_method, expires_at, created_at, revoked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)")
            .bind(token_hash)
            .bind(client_id)
            .bind(scope)
            .bind(resource)
            .bind(subject)
            .bind(auth_method)
            .bind(expires_at.to_rfc3339())
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn oauth_validate_access_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let row = sqlx::query("SELECT client_id, scope, resource, subject, auth_method, expires_at, revoked FROM oauth_access_tokens WHERE token_hash = ?")
            .bind(hash_secret(token))
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        if row.get::<i64, _>("revoked") != 0 {
            return Ok(None);
        }

        let expires_at: DateTime<Utc> = row.get::<String, _>("expires_at").parse()?;
        if expires_at < Utc::now() {
            return Ok(None);
        }

        Ok(Some(serde_json::json!({
            "client_id": row.get::<String, _>("client_id"),
            "scope": row.get::<String, _>("scope"),
            "resource": row.get::<Option<String>, _>("resource"),
            "subject": row.get::<String, _>("subject"),
            "auth_method": row.get::<String, _>("auth_method"),
            "expires_at": expires_at.to_rfc3339(),
        })))
    }

    pub async fn source_mark_success(&self, source: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO source_health (source_name, last_success_at, last_error_at, last_error) VALUES (?, ?, NULL, NULL) ON CONFLICT(source_name) DO UPDATE SET last_success_at = excluded.last_success_at, last_error_at = NULL, last_error = NULL")
            .bind(source)
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn source_mark_error(&self, source: &str, error: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO source_health (source_name, last_success_at, last_error_at, last_error) VALUES (?, NULL, ?, ?) ON CONFLICT(source_name) DO UPDATE SET last_error_at = excluded.last_error_at, last_error = excluded.last_error")
            .bind(source)
            .bind(Utc::now().to_rfc3339())
            .bind(error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn source_health(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT source_name, last_success_at, last_error_at, last_error FROM source_health ORDER BY source_name")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(serde_json::json!({
                "source": row.get::<String, _>("source_name"),
                "last_success_at": row.get::<Option<String>, _>("last_success_at"),
                "last_error_at": row.get::<Option<String>, _>("last_error_at"),
                "last_error": row.get::<Option<String>, _>("last_error"),
            }));
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn source_usage_record(
        &self,
        source: &str,
        window: &str,
        request_count: i64,
        success_count: i64,
        error_count: i64,
        timeout_count: i64,
        rate_limit_count: i64,
    ) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO source_usage (source, window, request_count, success_count, error_count, timeout_count, rate_limit_count, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source, window) DO UPDATE SET request_count = source_usage.request_count + excluded.request_count, success_count = source_usage.success_count + excluded.success_count, error_count = source_usage.error_count + excluded.error_count, timeout_count = source_usage.timeout_count + excluded.timeout_count, rate_limit_count = source_usage.rate_limit_count + excluded.rate_limit_count, last_seen = excluded.last_seen")
            .bind(source)
            .bind(window)
            .bind(request_count)
            .bind(success_count)
            .bind(error_count)
            .bind(timeout_count)
            .bind(rate_limit_count)
            .bind(Utc::now().to_rfc3339())
            .bind(Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn source_usage_list(&self) -> anyhow::Result<Vec<serde_json::Value>> {
        let rows = sqlx::query("SELECT source, window, request_count, success_count, error_count, timeout_count, rate_limit_count, first_seen, last_seen, reset_estimate FROM source_usage ORDER BY source, window")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(serde_json::json!({
                "source": row.get::<String, _>("source"),
                "window": row.get::<String, _>("window"),
                "request_count": row.get::<i64, _>("request_count"),
                "success_count": row.get::<i64, _>("success_count"),
                "error_count": row.get::<i64, _>("error_count"),
                "timeout_count": row.get::<i64, _>("timeout_count"),
                "rate_limit_count": row.get::<i64, _>("rate_limit_count"),
                "first_seen": row.get::<Option<String>, _>("first_seen"),
                "last_seen": row.get::<Option<String>, _>("last_seen"),
                "reset_estimate": row.get::<Option<String>, _>("reset_estimate"),
            }));
        }
        Ok(out)
    }
}

pub fn hash_secret(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_set_get_expiry() {
        let db = Database::connect("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");

        db.cache_set(CacheRecord {
            key: "k1".to_string(),
            module_id: "m".to_string(),
            target: "t".to_string(),
            value: serde_json::json!({"x":1}),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(10),
        })
        .await
        .expect("set");

        let hit = db.cache_get("k1").await.expect("get");
        assert!(hit.is_some());
    }

    #[tokio::test]
    async fn audit_insert_and_list() {
        let db = Database::connect("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");
        db.audit_insert(AuditEvent {
            request_id: "r1".to_string(),
            tool: "tool".to_string(),
            target: "target".to_string(),
            target_type: "ip".to_string(),
            sources_requested: vec!["a".to_string()],
            sources_used: vec!["a".to_string()],
            cache_hit: false,
            duration_ms: 5,
            status: "ok".to_string(),
            error_class: None,
            auth_method: "bearer".to_string(),
        })
        .await
        .expect("audit");

        let rows = db.audit_list(10).await.expect("list");
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn source_usage_accumulates() {
        let db = Database::connect("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");
        db.source_usage_record("nvd", "test-window", 1, 1, 0, 0, 0)
            .await
            .expect("record 1");
        db.source_usage_record("nvd", "test-window", 1, 0, 1, 0, 0)
            .await
            .expect("record 2");
        let rows = db.source_usage_list().await.expect("list");
        assert_eq!(rows[0]["request_count"], 2);
        assert_eq!(rows[0]["error_count"], 1);
    }
}
