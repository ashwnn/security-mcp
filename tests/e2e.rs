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
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.db_path);
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
    let db_path = std::env::temp_dir().join(format!("security-mcp-e2e-{}.sqlite", port));
    let bin = env!("CARGO_BIN_EXE_security-mcp");

    let mut cmd = Command::new(bin);
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
