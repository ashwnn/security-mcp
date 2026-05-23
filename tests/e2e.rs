use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use reqwest::redirect::Policy;
use serde_json::{Value, json};

struct TestServer {
    child: Child,
    base_url: String,
    db_path: PathBuf,
    work_dir: PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db_path);
        let _ = std::fs::remove_file(self.work_dir.join(".env"));
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

async fn wait_for_health(base_url: &str) {
    let client = reqwest::Client::new();
    for _ in 0..80 {
        if let Ok(resp) = client.get(format!("{base_url}/health")).send().await
            && resp.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server did not become healthy in time");
}

async fn start_server(extra_env: &[(&str, &str)]) -> TestServer {
    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let work_dir = std::env::temp_dir().join(format!("security-mcp-e2e-{port}"));
    std::fs::create_dir_all(&work_dir).expect("work dir");
    let db_path = work_dir.join("security-mcp.sqlite");
    let bin = env!("CARGO_BIN_EXE_security-mcp");

    let mut cmd = Command::new(bin);
    cmd.current_dir(&work_dir);
    cmd.env("SECURITY_MCP_BIND_ADDR", format!("127.0.0.1:{port}"))
        .env("SECURITY_MCP_PUBLIC_BASE_URL", &base_url)
        .env("SECURITY_MCP_DATABASE_PATH", &db_path)
        .env("SECURITY_MCP_PUBLIC_MODE", "false")
        .env("SECURITY_MCP_UI_LOCALHOST_ONLY", "true")
        .env("SECURITY_MCP_ENFORCE_MCP_ORIGIN", "true")
        .env("SECURITY_MCP_DEFAULT_TIMEOUT_SECONDS", "2")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let child = cmd.spawn().expect("spawn server");
    let server = TestServer {
        child,
        base_url,
        db_path,
        work_dir,
    };
    wait_for_health(&server.base_url).await;
    server
}

#[tokio::test]
async fn e2e_bearer_and_api_key_auth_for_mcp() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", "bearer-test-secret"),
        ("SECURITY_MCP_API_KEY", "api-test-secret"),
    ])
    .await;

    let client = reqwest::Client::new();

    let health = client
        .get(format!("{}/health", server.base_url))
        .send()
        .await
        .expect("health");
    assert_eq!(health.status(), reqwest::StatusCode::OK);

    let ui = client
        .get(format!("{}/", server.base_url))
        .send()
        .await
        .expect("ui");
    assert_eq!(ui.status(), reqwest::StatusCode::OK);

    let unauth = client
        .post(format!("{}/mcp", server.base_url))
        .json(&json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/list",
            "params":{}
        }))
        .send()
        .await
        .expect("unauth");
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    let api_key = client
        .post(format!("{}/mcp", server.base_url))
        .header("X-API-Key", "api-test-secret")
        .json(&json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/list",
            "params":{}
        }))
        .send()
        .await
        .expect("api key");
    assert_eq!(api_key.status(), reqwest::StatusCode::OK);

    let bearer = client
        .post(format!("{}/mcp", server.base_url))
        .bearer_auth("bearer-test-secret")
        .json(&json!({
            "jsonrpc":"2.0",
            "id":3,
            "method":"tools/call",
            "params":{
                "name":"security_tool_catalog",
                "arguments":{"category":"all","configured_only":false}
            }
        }))
        .send()
        .await
        .expect("bearer");
    assert_eq!(bearer.status(), reqwest::StatusCode::OK);
    let body: Value = bearer.json().await.expect("json");
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(
        body["result"]["internal_module_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
}

#[tokio::test]
async fn e2e_oauth_pkce_flow_and_mcp_access() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "true"),
        ("SECURITY_MCP_CONNECTOR_TOKEN", "connector-secret"),
        ("SECURITY_MCP_BEARER_TOKEN", ""),
        ("SECURITY_MCP_API_KEY", ""),
        ("SECURITY_MCP_OAUTH_REQUIRE_RESOURCE", "true"),
    ])
    .await;

    let no_redirect = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let register_resp = no_redirect
        .post(format!("{}/oauth/register", server.base_url))
        .json(&json!({
            "redirect_uris": ["http://localhost:3000/callback"],
            "token_endpoint_auth_method": "none"
        }))
        .send()
        .await
        .expect("register");
    assert_eq!(register_resp.status(), reqwest::StatusCode::OK);
    let register_json: Value = register_resp.json().await.expect("register json");
    let client_id = register_json["client_id"]
        .as_str()
        .expect("client id")
        .to_string();

    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let resource = format!("{}/mcp", server.base_url);

    let auth_resp = no_redirect
        .post(format!("{}/oauth/authorize", server.base_url))
        .form(&[
            ("connector_token", "connector-secret"),
            ("response_type", "code"),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("state", "abc123"),
            ("scope", "mcp:read mcp:tools"),
            ("resource", &resource),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .expect("authorize");
    assert_eq!(auth_resp.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    let location = auth_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("location")
        .to_string();
    let location_url = reqwest::Url::parse(&location).expect("redirect url");
    let code = location_url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .expect("code");

    let rejected_token_resp = no_redirect
        .post(format!("{}/oauth/token", server.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("client_id", client_id.as_str()),
            ("code_verifier", "wrong-verifier"),
            ("resource", resource.as_str()),
        ])
        .send()
        .await
        .expect("rejected token");
    assert_eq!(
        rejected_token_resp.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let token_resp = no_redirect
        .post(format!("{}/oauth/token", server.base_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://localhost:3000/callback"),
            ("client_id", client_id.as_str()),
            ("code_verifier", code_verifier),
            ("resource", resource.as_str()),
        ])
        .send()
        .await
        .expect("token");
    assert_eq!(token_resp.status(), reqwest::StatusCode::OK);
    let token_json: Value = token_resp.json().await.expect("token json");
    let access_token = token_json["access_token"].as_str().expect("access token");

    let mcp_resp = no_redirect
        .post(format!("{}/mcp", server.base_url))
        .bearer_auth(access_token)
        .json(&json!({
            "jsonrpc":"2.0",
            "id":7,
            "method":"tools/list",
            "params":{}
        }))
        .send()
        .await
        .expect("mcp");
    assert_eq!(mcp_resp.status(), reqwest::StatusCode::OK);
    let mcp_json: Value = mcp_resp.json().await.expect("mcp json");
    let tools = mcp_json["result"]["tools"].as_array().expect("tools array");
    assert!(!tools.is_empty());
}

#[tokio::test]
async fn e2e_oauth_registration_rejects_unsupported_auth_method() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "true"),
        ("SECURITY_MCP_CONNECTOR_TOKEN", "connector-secret"),
        ("SECURITY_MCP_BEARER_TOKEN", ""),
        ("SECURITY_MCP_API_KEY", ""),
    ])
    .await;

    let response = reqwest::Client::new()
        .post(format!("{}/oauth/register", server.base_url))
        .json(&json!({
            "redirect_uris": ["http://localhost:3000/callback"],
            "token_endpoint_auth_method": "unsupported_method"
        }))
        .send()
        .await
        .expect("register");

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn e2e_ui_settings_and_cache_buttons_work() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", ""),
        ("SECURITY_MCP_API_KEY", ""),
        ("SECURITY_MCP_CONNECTOR_TOKEN", ""),
    ])
    .await;

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let settings = client
        .get(format!("{}/settings", server.base_url))
        .send()
        .await
        .expect("settings");
    assert_eq!(settings.status(), reqwest::StatusCode::OK);
    let settings_html = settings.text().await.expect("settings html");
    assert!(settings_html.contains("Save auth settings"));
    assert!(settings_html.contains("Rotate all tokens"));
    assert!(settings_html.contains("data-copy-endpoint"));
    assert!(settings_html.contains("Regenerate"));

    let save_resp = client
        .post(format!("{}/settings/save", server.base_url))
        .form(&[
            ("bearer_token", "saved-bearer"),
            ("api_key", "saved-api"),
            ("connector_token", "saved-connector"),
            ("oauth_enabled", "true"),
            ("public_mode", "false"),
            ("api_key_query_enabled", "true"),
        ])
        .send()
        .await
        .expect("save");
    assert_eq!(save_resp.status(), reqwest::StatusCode::SEE_OTHER);
    let location = save_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .expect("redirect location");
    assert!(location.starts_with("/settings?message="));
    assert!(location.contains("restart"));

    let env_text = std::fs::read_to_string(server.work_dir.join(".env")).expect("env file");
    assert!(env_text.contains("SECURITY_MCP_BEARER_TOKEN=saved-bearer"));
    assert!(env_text.contains("SECURITY_MCP_API_KEY=saved-api"));
    assert!(env_text.contains("SECURITY_MCP_CONNECTOR_TOKEN=saved-connector"));
    assert!(env_text.contains("SECURITY_MCP_OAUTH_ENABLED=true"));
    assert!(env_text.contains("SECURITY_MCP_API_KEY_QUERY_ENABLED=true"));

    let generate_resp = client
        .post(format!("{}/settings/generate-auth", server.base_url))
        .send()
        .await
        .expect("generate");
    assert_eq!(generate_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        generate_resp
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let generate_html = generate_resp.text().await.expect("generate html");
    assert!(generate_html.contains("Generated Tokens"));

    let env_after_generate =
        std::fs::read_to_string(server.work_dir.join(".env")).expect("env after generate");
    assert!(env_after_generate.contains("SECURITY_MCP_BEARER_TOKEN="));
    assert!(env_after_generate.contains("SECURITY_MCP_API_KEY="));
    assert!(env_after_generate.contains("SECURITY_MCP_CONNECTOR_TOKEN="));
    let generated_bearer = env_after_generate
        .lines()
        .find_map(|line| line.strip_prefix("SECURITY_MCP_BEARER_TOKEN="))
        .expect("generated bearer");
    assert!(generate_html.contains(generated_bearer));
    assert!(generate_html.contains("restart"));

    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&server.db_path)
            .create_if_missing(true),
    )
    .await
    .expect("db");
    sqlx::query(
        "INSERT INTO cache_entries (key, module_id, target, value_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("0123456789abcdef0123456789abcdef")
    .bind("module-one")
    .bind("example.com")
    .bind(serde_json::to_string(&serde_json::json!({"ok": true})).expect("json"))
    .bind(chrono::Utc::now().to_rfc3339())
    .bind((chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339())
    .execute(&pool)
    .await
    .expect("cache set");

    let cache_page = client
        .get(format!("{}/cache", server.base_url))
        .send()
        .await
        .expect("cache page");
    assert_eq!(cache_page.status(), reqwest::StatusCode::OK);
    let cache_html = cache_page.text().await.expect("cache html");
    assert!(cache_html.contains("module-one"));
    assert!(cache_html.contains("Delete"));
    assert!(cache_html.contains("Clear Cache"));

    let delete_resp = client
        .post(format!(
            "{}/cache/delete/{}",
            server.base_url, "0123456789abcdef0123456789abcdef"
        ))
        .send()
        .await
        .expect("delete");
    assert_eq!(delete_resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(
        delete_resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/cache")
    );

    let cache_after_delete = client
        .get(format!("{}/cache", server.base_url))
        .send()
        .await
        .expect("cache after delete");
    let cache_after_delete_html = cache_after_delete
        .text()
        .await
        .expect("cache after delete html");
    assert!(!cache_after_delete_html.contains("module-one"));

    sqlx::query(
        "INSERT INTO cache_entries (key, module_id, target, value_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind("fedcba9876543210fedcba9876543210")
    .bind("module-two")
    .bind("example.org")
    .bind(serde_json::to_string(&serde_json::json!({"ok": true})).expect("json"))
    .bind(chrono::Utc::now().to_rfc3339())
    .bind((chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339())
    .execute(&pool)
    .await
    .expect("cache set clear");

    let clear_resp = client
        .post(format!("{}/cache/clear", server.base_url))
        .send()
        .await
        .expect("clear");
    assert_eq!(clear_resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(
        clear_resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok()),
        Some("/cache")
    );

    let cache_after_clear = client
        .get(format!("{}/cache", server.base_url))
        .send()
        .await
        .expect("cache after clear");
    let cache_after_clear_html = cache_after_clear
        .text()
        .await
        .expect("cache after clear html");
    assert!(cache_after_clear_html.contains("Cache is empty."));
}

#[tokio::test]
async fn e2e_remote_ui_token_management_requires_admin_scope() {
    let server = start_server(&[
        ("SECURITY_MCP_UI_LOCALHOST_ONLY", "false"),
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", "reader-token"),
        ("SECURITY_MCP_BEARER_SCOPES", "mcp:read mcp:tools"),
        ("SECURITY_MCP_API_KEY", ""),
    ])
    .await;

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    let settings = client
        .get(format!("{}/settings", server.base_url))
        .bearer_auth("reader-token")
        .send()
        .await
        .expect("settings");
    assert_eq!(settings.status(), reqwest::StatusCode::FORBIDDEN);

    let copied = client
        .post(format!("{}/settings/token/bearer/copy", server.base_url))
        .bearer_auth("reader-token")
        .send()
        .await
        .expect("copy");
    assert_eq!(copied.status(), reqwest::StatusCode::FORBIDDEN);
    assert_ne!(copied.text().await.expect("copy body"), "reader-token");

    let rotated = client
        .post(format!(
            "{}/settings/token/bearer/regenerate",
            server.base_url
        ))
        .bearer_auth("reader-token")
        .send()
        .await
        .expect("rotate");
    assert_eq!(rotated.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(!server.work_dir.join(".env").exists());

    let clear_cache = client
        .post(format!("{}/cache/clear", server.base_url))
        .bearer_auth("reader-token")
        .send()
        .await
        .expect("clear cache");
    assert_eq!(clear_cache.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn e2e_remote_admin_token_rotation_displays_replacement_before_restart() {
    let server = start_server(&[
        ("SECURITY_MCP_UI_LOCALHOST_ONLY", "false"),
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", "admin-token"),
        ("SECURITY_MCP_BEARER_SCOPES", "mcp:read mcp:tools mcp:admin"),
        ("SECURITY_MCP_API_KEY", ""),
    ])
    .await;

    let response = reqwest::Client::new()
        .post(format!(
            "{}/settings/token/bearer/regenerate",
            server.base_url
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("rotate admin token");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let html = response.text().await.expect("rotation body");
    let env = std::fs::read_to_string(server.work_dir.join(".env")).expect("env");
    let generated = env
        .lines()
        .find_map(|line| line.strip_prefix("SECURITY_MCP_BEARER_TOKEN="))
        .expect("generated token");
    assert_ne!(generated, "admin-token");
    assert!(html.contains(generated));
    assert!(html.contains("restart"));
}

#[tokio::test]
async fn e2e_local_ui_rejects_cross_origin_auth_mutation() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", ""),
        ("SECURITY_MCP_API_KEY", ""),
        ("SECURITY_MCP_CONNECTOR_TOKEN", ""),
    ])
    .await;

    let response = reqwest::Client::new()
        .post(format!("{}/settings/generate-auth", server.base_url))
        .header("Origin", "https://attacker.example")
        .send()
        .await
        .expect("cross origin rotate");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(!server.work_dir.join(".env").exists());
}

#[tokio::test]
async fn e2e_local_ui_rejects_non_loopback_host_header() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", ""),
        ("SECURITY_MCP_API_KEY", ""),
    ])
    .await;

    let response = reqwest::Client::new()
        .get(format!("{}/settings", server.base_url))
        .header("Host", "attacker.example")
        .send()
        .await
        .expect("rebinding request");

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn e2e_mcp_tool_call_requires_tools_scope() {
    let server = start_server(&[
        ("SECURITY_MCP_OAUTH_ENABLED", "false"),
        ("SECURITY_MCP_BEARER_TOKEN", "read-only-token"),
        ("SECURITY_MCP_BEARER_SCOPES", "mcp:read"),
        ("SECURITY_MCP_API_KEY", ""),
    ])
    .await;

    let response = reqwest::Client::new()
        .post(format!("{}/mcp", server.base_url))
        .bearer_auth("read-only-token")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "security_tool_catalog",
                "arguments": {}
            }
        }))
        .send()
        .await
        .expect("tool call");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.expect("mcp response");
    assert_eq!(
        body["error"]["message"],
        "insufficient scope: mcp:tools required"
    );
}
