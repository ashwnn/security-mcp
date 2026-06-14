use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::oauth::canonical_resource;
use crate::types::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthIdentity {
    pub method: String,
    pub subject: String,
    pub scopes: Vec<String>,
}

#[derive(Clone)]
pub struct AuthLayer {
    state: Arc<AppState>,
}

impl AuthLayer {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn protect(&self, router: Router) -> Router {
        router.layer(middleware::from_fn_with_state(
            self.state.clone(),
            auth_middleware,
        ))
    }
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if is_public_path(req.uri().path()) {
        return next.run(req).await;
    }

    let rate_limit_key = auth_rate_limit_key(&state, &req);
    if !state.auth_rate_limiter.check(&rate_limit_key) {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }

    match authenticate(&state, req.headers(), req.uri().query()).await {
        Ok(Some(identity)) => {
            req.extensions_mut().insert(identity);
            next.run(req).await
        }
        Ok(None) => {
            if !state.config.public_mode
                && state.config.bearer_token.is_none()
                && state.config.api_key.is_none()
                && !state.config.oauth_enabled
            {
                return next.run(req).await;
            }
            unauthorized_response(&state)
        }
        Err(_) => unauthorized_response(&state),
    }
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    query: Option<&str>,
) -> anyhow::Result<Option<AuthIdentity>> {
    if let Some(token) = bearer_from_headers(headers) {
        if let Some(expected) = state.config.bearer_token.as_deref()
            && constant_time_eq(expected, &token)
        {
            return Ok(Some(AuthIdentity {
                method: "bearer".to_string(),
                subject: "static-bearer".to_string(),
                scopes: state.config.bearer_scopes.clone(),
            }));
        }

        if state.config.oauth_enabled
            && let Some(data) = state.db.oauth_validate_access_token(&token).await?
        {
            if !valid_token_resource(&data, state) {
                return Ok(None);
            }
            let scopes = data["scope"]
                .as_str()
                .unwrap_or("mcp:read mcp:tools")
                .split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(AuthIdentity {
                method: "oauth_access_token".to_string(),
                subject: data["subject"].as_str().unwrap_or("oauth-user").to_string(),
                scopes,
            }));
        }
    }

    if let Some(key) = header_token(headers, &state.config.api_key_header)
        && let Some(expected) = state.config.api_key.as_deref()
        && constant_time_eq(expected, &key)
    {
        return Ok(Some(AuthIdentity {
            method: "api_key_header".to_string(),
            subject: "api-key".to_string(),
            scopes: state.config.api_key_scopes.clone(),
        }));
    }

    if state.config.api_key_query_enabled
        && let Some(token) = query_token(query, &state.config.api_key_query_name)
        && let Some(expected) = state.config.api_key.as_deref()
        && constant_time_eq(expected, &token)
    {
        return Ok(Some(AuthIdentity {
            method: "api_key_query".to_string(),
            subject: "api-key-query".to_string(),
            scopes: state.config.api_key_scopes.clone(),
        }));
    }

    Ok(None)
}

fn valid_token_resource(data: &serde_json::Value, state: &AppState) -> bool {
    let expected = canonical_resource(&state.config);
    match data["resource"].as_str() {
        Some(resource) => resource == expected,
        None => !state.config.oauth_require_resource,
    }
}

fn unauthorized_response(state: &AppState) -> Response {
    let challenge = if state.config.oauth_enabled {
        format!(
            "Bearer realm=\"security-mcp\", resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
            state.config.public_base_url.as_str().trim_end_matches('/')
        )
    } else {
        "Bearer realm=\"security-mcp\"".to_string()
    };
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", challenge)],
        "authentication required",
    )
        .into_response()
}

fn auth_rate_limit_key(state: &AppState, req: &Request<axum::body::Body>) -> String {
    let client = request_client_key(state, req.headers(), req.extensions());
    format!("auth:{}:{}", req.uri().path(), client)
}

fn request_client_key(
    state: &AppState,
    headers: &HeaderMap,
    extensions: &http::Extensions,
) -> String {
    if state.config.trust_proxy_headers
        && let Some(ip) = forwarded_ip(headers)
    {
        return ip;
    }

    extensions
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
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

fn is_public_path(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/.well-known/oauth-authorization-server"
            | "/.well-known/openid-configuration"
            | "/.well-known/oauth-protected-resource"
            | "/oauth/authorize"
            | "/oauth/authorize/"
            | "/oauth/token"
            | "/oauth/token/"
            | "/oauth/register"
            | "/oauth/register/"
    )
}

fn bearer_from_headers(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?.trim();
    if auth.to_ascii_lowercase().starts_with("bearer ") {
        return Some(auth[7..].trim().to_string());
    }
    None
}

fn header_token(headers: &HeaderMap, header_name: &str) -> Option<String> {
    headers
        .get(header_name)
        .or_else(|| headers.get(header_name.to_ascii_lowercase()))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
}

fn query_token(query: Option<&str>, param_name: &str) -> Option<String> {
    let query = query?;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key == param_name {
            return Some(value.to_string());
        }
    }
    None
}

fn constant_time_eq(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn bearer_extracts() {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("Bearer abc"));
        assert_eq!(bearer_from_headers(&h), Some("abc".to_string()));
    }

    #[test]
    fn query_token_extracts() {
        assert_eq!(query_token(Some("api_key=abc"), "api_key"), Some("abc".to_string()));
    }
}
