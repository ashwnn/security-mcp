use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{
    Json, Router,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration as ChronoDuration, Utc};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::auth::AuthLayer;
use crate::db::OauthCodeRecord;
use crate::types::AppState;

#[derive(Clone)]
pub struct SimpleRateLimiter {
    inner: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    max_requests: u32,
    window: Duration,
}

impl SimpleRateLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        })
    }

    pub fn check(&self, key: &str) -> bool {
        let mut guard = self.inner.lock().expect("rate limit lock");
        let now = Instant::now();
        let entry = guard.entry(key.to_string()).or_insert((0, now));

        if now.duration_since(entry.1) > self.window {
            *entry = (0, now);
        }

        if entry.0 >= self.max_requests {
            return false;
        }

        entry.0 += 1;
        true
    }
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Deserialize)]
pub struct AuthorizeForm {
    pub connector_token: String,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: Option<String>,
    pub resource: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub code_verifier: String,
    pub client_secret: Option<String>,
    pub resource: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    client_id: String,
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    scope: String,
}

pub fn router(state: Arc<AppState>, _auth_layer: AuthLayer) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server_metadata),
        )
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        .route("/oauth/authorize", get(get_authorize).post(post_authorize))
        .route("/oauth/authorize/", get(get_authorize).post(post_authorize))
        .route("/oauth/token", post(post_token))
        .route("/oauth/token/", post(post_token))
        .route("/oauth/register", post(post_register))
        .route("/oauth/register/", post(post_register))
        .with_state(state)
}

async fn oauth_authorization_server_metadata(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let issuer = state.config.oauth_issuer.as_str().trim_end_matches('/');
    let scopes = state
        .config
        .oauth_allowed_scopes
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": scopes,
    }))
}

async fn openid_configuration(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    oauth_authorization_server_metadata(State(state)).await
}

async fn oauth_protected_resource(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base = state.config.public_base_url.as_str().trim_end_matches('/');
    Json(serde_json::json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [state.config.oauth_issuer.as_str()],
    }))
}

async fn get_authorize(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let rate_limit_key = oauth_rate_limit_key(
        &state,
        "oauth_authorize_get",
        Some(&query.client_id),
        &headers,
        connect_info,
    );
    if !state.auth_rate_limiter.check(&rate_limit_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    if !state.config.oauth_enabled {
        return (StatusCode::NOT_FOUND, "oauth disabled").into_response();
    }

    if let Err(err) = validate_authorize_request(&query, &state).await {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    let default_scope = state.config.oauth_default_scopes.join(" ");
    let html = format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>Security MCP OAuth Login</title></head><body><h1>Security MCP OAuth</h1><p>Enter connector token to authorize client <code>{}</code>.</p><form method='post' action='/oauth/authorize'><input type='password' name='connector_token' required /><input type='hidden' name='response_type' value='{}'/><input type='hidden' name='client_id' value='{}'/><input type='hidden' name='redirect_uri' value='{}'/><input type='hidden' name='state' value='{}'/><input type='hidden' name='scope' value='{}'/><input type='hidden' name='resource' value='{}'/><input type='hidden' name='code_challenge' value='{}'/><input type='hidden' name='code_challenge_method' value='{}'/><button type='submit'>Authorize</button></form></body></html>",
        html_escape(&query.client_id),
        html_escape(&query.response_type),
        html_escape(&query.client_id),
        html_escape(&query.redirect_uri),
        html_escape(query.state.as_deref().unwrap_or("")),
        html_escape(query.scope.as_deref().unwrap_or(&default_scope)),
        html_escape(query.resource.as_deref().unwrap_or("")),
        html_escape(&query.code_challenge),
        html_escape(&query.code_challenge_method),
    );
    Html(html).into_response()
}

async fn post_authorize(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeForm>,
) -> Response {
    let rate_limit_key = oauth_rate_limit_key(
        &state,
        "oauth_authorize_post",
        Some(&form.client_id),
        &headers,
        connect_info,
    );
    if !state.auth_rate_limiter.check(&rate_limit_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    if !state.config.oauth_enabled {
        return (StatusCode::NOT_FOUND, "oauth disabled").into_response();
    }

    let query = AuthorizeQuery {
        response_type: form.response_type.clone(),
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        state: form.state.clone(),
        scope: form.scope.clone(),
        resource: form.resource.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
    };

    if let Err(err) = validate_authorize_request(&query, &state).await {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    let Some(connector_token) = state.config.connector_token.as_deref() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "connector token not configured",
        )
            .into_response();
    };

    if !constant_time_eq(connector_token, &form.connector_token) {
        warn!("oauth login rejected");
        return (StatusCode::UNAUTHORIZED, "invalid token").into_response();
    }

    let code = random_token(32);
    let scope = match sanitize_requested_scopes(
        form.scope.as_deref(),
        &state.config.oauth_allowed_scopes,
        &state.config.oauth_default_scopes,
    ) {
        Ok(scopes) => scopes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    let expires = Utc::now() + ChronoDuration::seconds(state.config.auth_code_ttl_seconds);

    if let Err(err) = state
        .db
        .oauth_store_code(OauthCodeRecord {
            code: code.clone(),
            client_id: form.client_id.clone(),
            redirect_uri: form.redirect_uri.clone(),
            code_challenge: form.code_challenge.clone(),
            code_challenge_method: form.code_challenge_method.clone(),
            scope: scope.clone(),
            state: form.state.clone(),
            subject: "connector-user".to_string(),
            expires_at: expires,
        })
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to store code: {err}"),
        )
            .into_response();
    }

    let mut redirect = format!("{}?code={}", form.redirect_uri, urlencoding::encode(&code));
    if let Some(state_param) = form.state {
        redirect.push_str(&format!("&state={}", urlencoding::encode(&state_param)));
    }
    Redirect::temporary(&redirect).into_response()
}

async fn post_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let rate_limit_key = oauth_rate_limit_key(
        &state,
        "oauth_token",
        Some(&form.client_id),
        &headers,
        connect_info,
    );
    if !state.auth_rate_limiter.check(&rate_limit_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    if !state.config.oauth_enabled {
        return (StatusCode::NOT_FOUND, "oauth disabled").into_response();
    }

    if form.grant_type != "authorization_code" {
        return (StatusCode::BAD_REQUEST, "unsupported grant_type").into_response();
    }
    if let Err(err) = validate_resource_parameter(form.resource.as_deref(), &state.config) {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    let code_data = match state.db.oauth_get_valid_code(&form.code).await {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired code").into_response(),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db error: {err}"),
            )
                .into_response();
        }
    };

    if code_data["client_id"] != form.client_id {
        return (StatusCode::BAD_REQUEST, "client mismatch").into_response();
    }
    if code_data["redirect_uri"] != form.redirect_uri {
        return (StatusCode::BAD_REQUEST, "redirect_uri mismatch").into_response();
    }

    let challenge = code_data["code_challenge"].as_str().unwrap_or_default();
    let method = code_data["code_challenge_method"]
        .as_str()
        .unwrap_or_default();
    if method != "S256" {
        return (StatusCode::BAD_REQUEST, "unsupported code challenge method").into_response();
    }

    if pkce_s256(&form.code_verifier) != challenge {
        return (StatusCode::BAD_REQUEST, "invalid code_verifier").into_response();
    }

    let client = match state.db.oauth_get_client(&form.client_id).await {
        Ok(client) => client,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db error: {err}"),
            )
                .into_response();
        }
    };

    let Some((_id, secret_hash, _redirects, auth_method)) = client else {
        if state.config.require_registered_oauth_clients {
            return (StatusCode::BAD_REQUEST, "unknown client_id").into_response();
        }
        return (StatusCode::BAD_REQUEST, "client registration required").into_response();
    };

    if auth_method != "none" {
        let provided = resolve_client_secret(&headers, &form);
        let Some(provided) = provided else {
            return (StatusCode::UNAUTHORIZED, "missing client authentication").into_response();
        };
        let Some(expected_hash) = secret_hash else {
            return (
                StatusCode::UNAUTHORIZED,
                "client not configured for secret auth",
            )
                .into_response();
        };
        if crate::db::hash_secret(&provided) != expected_hash {
            return (StatusCode::UNAUTHORIZED, "invalid client credentials").into_response();
        }
    }

    match state.db.oauth_consume_code(&form.code).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::BAD_REQUEST, "invalid or expired code").into_response(),
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db error: {err}"),
            )
                .into_response();
        }
    }

    let access_token = random_token(48);
    let scope = code_data["scope"].as_str().unwrap_or("mcp:read mcp:tools");
    let expires = Utc::now() + ChronoDuration::seconds(state.config.access_token_ttl_seconds);

    if let Err(err) = state
        .db
        .oauth_store_access_token(
            &access_token,
            &form.client_id,
            scope,
            code_data["subject"].as_str().unwrap_or("connector-user"),
            "oauth",
            expires,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {err}"),
        )
            .into_response();
    }

    Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.access_token_ttl_seconds,
        scope: scope.to_string(),
    })
    .into_response()
}

async fn post_register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Response {
    let rate_limit_key =
        oauth_rate_limit_key(&state, "oauth_register", None, &headers, connect_info);
    if !state.auth_rate_limiter.check(&rate_limit_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    if payload.redirect_uris.is_empty() {
        return (StatusCode::BAD_REQUEST, "redirect_uris required").into_response();
    }
    let _client_name = payload.client_name.clone();

    for uri in &payload.redirect_uris {
        if !is_valid_redirect_uri(uri) {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid redirect uri: {uri}"),
            )
                .into_response();
        }
    }

    let client_id = format!("secmcp_{}", random_token(10));
    let auth_method = payload
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            "unsupported token_endpoint_auth_method",
        )
            .into_response();
    }

    let client_secret = if auth_method == "none" {
        None
    } else {
        Some(random_token(40))
    };

    if let Err(err) = state
        .db
        .oauth_store_client(
            &client_id,
            client_secret.as_deref(),
            &payload.redirect_uris,
            &auth_method,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("db error: {err}"),
        )
            .into_response();
    }

    Json(RegisterResponse {
        client_id,
        client_secret,
        redirect_uris: payload.redirect_uris,
        token_endpoint_auth_method: auth_method,
    })
    .into_response()
}

async fn validate_authorize_request(
    query: &AuthorizeQuery,
    state: &AppState,
) -> Result<(), String> {
    if query.response_type != "code" {
        return Err("response_type must be code".to_string());
    }
    if query.code_challenge_method != "S256" {
        return Err("code_challenge_method must be S256".to_string());
    }
    if !is_valid_redirect_uri(&query.redirect_uri) {
        return Err("invalid redirect_uri".to_string());
    }
    validate_resource_parameter(query.resource.as_deref(), &state.config)?;

    let client = state
        .db
        .oauth_get_client(&query.client_id)
        .await
        .map_err(|_| "client lookup failed".to_string())?;
    if state.config.require_registered_oauth_clients && client.is_none() {
        return Err("unknown client_id".to_string());
    }
    if let Some((_id, _secret, redirects, _method)) = client
        && !redirects.contains(&query.redirect_uri)
    {
        return Err("redirect_uri not allowed for client".to_string());
    }

    Ok(())
}

fn is_valid_redirect_uri(uri: &str) -> bool {
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };

    if parsed.scheme() == "https" {
        return true;
    }

    if parsed.scheme() == "http"
        && let Some(host) = parsed.host_str()
    {
        return host == "127.0.0.1" || host == "localhost";
    }

    false
}

fn resolve_client_secret(headers: &HeaderMap, form: &TokenForm) -> Option<String> {
    if let Some(secret) = &form.client_secret {
        return Some(secret.to_string());
    }

    let header = headers.get("authorization")?;
    let value = header.to_str().ok()?;
    if !value.to_ascii_lowercase().starts_with("basic ") {
        return None;
    }
    let raw = &value[6..];
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_client_id, secret) = decoded.split_once(':')?;
    Some(secret.to_string())
}

fn pkce_s256(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

fn random_token(len: usize) -> String {
    let mut rng = rand::rng();
    Alphanumeric.sample_string(&mut rng, len)
}

fn constant_time_eq(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn sanitize_requested_scopes(
    requested: Option<&str>,
    allowed: &[String],
    defaults: &[String],
) -> Result<String, String> {
    let requested_scopes = requested
        .unwrap_or("")
        .split_whitespace()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let mut resolved = if requested_scopes.is_empty() {
        defaults.to_vec()
    } else {
        requested_scopes
    };
    resolved.sort();
    resolved.dedup();

    if resolved.is_empty() {
        return Err("scope set is empty".to_string());
    }
    if let Some(invalid) = resolved.iter().find(|scope| !allowed.contains(scope)) {
        return Err(format!("unsupported scope: {invalid}"));
    }

    Ok(resolved.join(" "))
}

fn validate_resource_parameter(
    resource: Option<&str>,
    config: &crate::config::Config,
) -> Result<(), String> {
    let canonical = format!(
        "{}/mcp",
        config.public_base_url.as_str().trim_end_matches('/')
    );

    let Some(value) = resource else {
        if config.oauth_require_resource {
            return Err("resource parameter is required".to_string());
        }
        return Ok(());
    };

    if value != canonical {
        return Err("invalid resource parameter".to_string());
    }
    Ok(())
}

fn oauth_rate_limit_key(
    state: &AppState,
    route: &str,
    client_id: Option<&str>,
    headers: &HeaderMap,
    connect_info: SocketAddr,
) -> String {
    let client_id = client_id.unwrap_or("no-client");
    let ip = request_ip_hint(state, headers, connect_info);
    format!("{route}:{client_id}:{ip}")
}

fn request_ip_hint(state: &AppState, headers: &HeaderMap, connect_info: SocketAddr) -> String {
    if state.config.trust_proxy_headers
        && let Some(ip) = forwarded_ip(headers)
    {
        return ip;
    }
    connect_info.ip().to_string()
}

fn forwarded_ip(headers: &HeaderMap) -> Option<String> {
    for header in ["cf-connecting-ip", "true-client-ip", "x-forwarded-for"] {
        let value = headers.get(header)?.to_str().ok()?.trim();
        if value.is_empty() {
            continue;
        }
        if header == "x-forwarded-for" {
            let first = value.split(',').next().map(str::trim).unwrap_or_default();
            if !first.is_empty() {
                return Some(first.to_string());
            }
            continue;
        }
        return Some(value.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use url::Url;

    #[test]
    fn validates_redirect_uri() {
        assert!(is_valid_redirect_uri("https://example.com/cb"));
        assert!(is_valid_redirect_uri("http://localhost:3000/cb"));
        assert!(!is_valid_redirect_uri("http://evil.com/cb"));
    }

    #[test]
    fn pkce_roundtrip() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn reject_unsupported_scope() {
        let result = sanitize_requested_scopes(
            Some("mcp:read mcp:admin"),
            &["mcp:read".to_string(), "mcp:tools".to_string()],
            &["mcp:read".to_string()],
        );
        assert!(result.is_err());
    }

    #[test]
    fn requires_resource_when_enabled() {
        let config = Config {
            bind_addr: "127.0.0.1:8080".parse().expect("addr"),
            public_base_url: Url::parse("https://security.example.com").expect("url"),
            oauth_issuer: Url::parse("https://security.example.com").expect("url"),
            database_path: ":memory:".to_string(),
            public_mode: false,
            bearer_token: None,
            bearer_scopes: vec!["mcp:read".to_string()],
            api_key: None,
            api_key_scopes: vec!["mcp:read".to_string()],
            api_key_header: "X-API-Key".to_string(),
            api_key_query_enabled: false,
            api_key_query_name: "api_key".to_string(),
            connector_token: Some("x".to_string()),
            oauth_enabled: true,
            oauth_allowed_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            oauth_default_scopes: vec!["mcp:read".to_string()],
            oauth_require_resource: true,
            require_registered_oauth_clients: true,
            access_token_ttl_seconds: 3600,
            auth_code_ttl_seconds: 300,
            expert_tool_enabled: false,
            cache_enabled: true,
            default_timeout_seconds: 15,
            max_request_body_bytes: 1024 * 1024,
            allow_private_targets: false,
            trust_proxy_headers: false,
            enforce_mcp_origin: true,
            auth_rate_limit_per_minute: 120,
            lookup_rate_limit_per_minute: 120,
            ui_localhost_only: true,
            log_level: "info".to_string(),
            nvd_api_key: None,
            shodan_api_key: None,
            greynoise_api_key: None,
            abuseipdb_api_key: None,
            virustotal_api_key: None,
            urlscan_api_key: None,
            github_token: None,
            circl_pd_user: None,
            circl_pd_password: None,
            rate_limit_default_plan: "free".to_string(),
            rate_limit_warn_remaining_percent: 20.0,
            rate_limit_block_remaining_percent: 5.0,
            rate_limit_soft_block_enabled: true,
            censys_api_id: None,
            censys_api_secret: None,
            securitytrails_api_key: None,
            otx_api_key: None,
            misp_base_url: None,
            misp_api_key: None,
            misp_verify_tls: true,
            google_safe_browsing_api_key: None,
            pulsedive_api_key: None,
            hybrid_analysis_api_key: None,
        };

        let missing = validate_resource_parameter(None, &config);
        assert!(missing.is_err());
        let good = validate_resource_parameter(Some("https://security.example.com/mcp"), &config);
        assert!(good.is_ok());
    }
}
