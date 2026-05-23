use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{AuthIdentity, AuthLayer};
use crate::modules::{
    security_compare, security_investigate, security_investigate_cve,
    security_investigate_indicator, security_run_tool, security_scan_dependencies,
    security_tool_catalog,
};
use crate::types::{
    AppState, CompareInput, CveInvestigationInput, DependencyScanInput,
    IndicatorInvestigationInput, InvestigationInput, RunToolInput, ToolCatalogInput,
};

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

pub fn router(state: Arc<AppState>, auth_layer: AuthLayer) -> Router {
    let protected = Router::new()
        .route("/mcp", post(handle_mcp))
        .with_state(state);
    auth_layer.protect(protected)
}

async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<AuthIdentity>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    if state.config.enforce_mcp_origin && !valid_origin(&headers, &state.config) {
        return rpc_error(request.id, -32001, "invalid origin");
    }

    if let Err(err) = validate_mcp_protocol_header(&headers) {
        return (
            StatusCode::BAD_REQUEST,
            Json(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32600,
                    message: err,
                }),
            }),
        )
            .into_response();
    }

    if request.jsonrpc != "2.0" {
        return rpc_error(request.id, -32600, "invalid jsonrpc version");
    }

    let rate_key = format!(
        "mcp:{}:{}:{}",
        identity.subject, identity.method, request.method
    );
    if !state.auth_rate_limiter.check(&rate_key) {
        return rpc_error(request.id, -32029, "rate limit exceeded");
    }

    match dispatch(&state, &identity, &request.method, request.params).await {
        Ok(result) => Json(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: Some(result),
            error: None,
        })
        .into_response(),
        Err(err) => {
            let msg = err.to_string();
            if msg == "method not found" {
                rpc_error(request.id, -32601, &msg)
            } else {
                rpc_error(request.id, -32000, &msg)
            }
        }
    }
}

async fn dispatch(
    state: &AppState,
    auth: &AuthIdentity,
    method: &str,
    params: Value,
) -> anyhow::Result<Value> {
    match method {
        "initialize" => Ok(serde_json::json!({
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "security-mcp", "version": env!("CARGO_PKG_VERSION")},
            "protocolVersion": "2025-03-26",
        })),
        "tools/list" | "mcp.list_tools" => {
            let tools = state
                .registry
                .high_level_tools()
                .into_iter()
                .map(|name| serde_json::json!({"name": name}))
                .collect::<Vec<_>>();
            Ok(serde_json::json!({ "tools": tools }))
        }
        "tools/call" | "mcp.call_tool" => {
            let tool_name = params["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing tool name"))?;
            let args = params["arguments"].clone();
            call_tool(state, auth, tool_name, args).await
        }
        _ => Err(anyhow::anyhow!("method not found")),
    }
}

async fn call_tool(
    state: &AppState,
    auth: &AuthIdentity,
    tool_name: &str,
    args: Value,
) -> anyhow::Result<Value> {
    match tool_name {
        "security_investigate" => {
            let input: InvestigationInput = serde_json::from_value(args)?;
            Ok(serde_json::to_value(
                security_investigate(state, input, auth).await?,
            )?)
        }
        "security_investigate_cve" => {
            let input: CveInvestigationInput = serde_json::from_value(args)?;
            Ok(serde_json::to_value(
                security_investigate_cve(state, input, auth).await?,
            )?)
        }
        "security_investigate_indicator" => {
            let input: IndicatorInvestigationInput = serde_json::from_value(args)?;
            Ok(serde_json::to_value(
                security_investigate_indicator(state, input, auth).await?,
            )?)
        }
        "security_scan_dependencies" => {
            let input: DependencyScanInput = serde_json::from_value(args)?;
            Ok(serde_json::to_value(
                security_scan_dependencies(state, input, auth).await?,
            )?)
        }
        "security_compare" => {
            let input: CompareInput = serde_json::from_value(args)?;
            security_compare(state, input, auth).await
        }
        "security_tool_catalog" => {
            let input: ToolCatalogInput = serde_json::from_value(args)?;
            Ok(security_tool_catalog(&state.registry, &state.config, input))
        }
        "security_run_tool" => {
            let input: RunToolInput = serde_json::from_value(args)?;
            let _requested_output_mode = input.output_mode.clone();
            security_run_tool(state, &input.tool_id, input.args, auth).await
        }
        _ => Err(anyhow::anyhow!("unknown tool")),
    }
}

fn rpc_error(id: Option<Value>, code: i32, message: &str) -> Response {
    (
        StatusCode::OK,
        Json(JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
            }),
        }),
    )
        .into_response()
}

fn validate_mcp_protocol_header(headers: &HeaderMap) -> Result<(), String> {
    let Some(value) = headers.get("MCP-Protocol-Version") else {
        return Ok(());
    };
    let Ok(value) = value.to_str() else {
        return Err("invalid MCP-Protocol-Version".to_string());
    };
    let supported = ["2025-03-26", "2025-06-18", "2025-11-25"];
    if supported.contains(&value) {
        Ok(())
    } else {
        Err("unsupported MCP-Protocol-Version".to_string())
    }
}

fn valid_origin(headers: &HeaderMap, config: &crate::config::Config) -> bool {
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let base = format!(
        "{}://{}",
        config.public_base_url.scheme(),
        config.public_base_url.host_str().unwrap_or_default()
    );
    let mut allowed = vec![base.clone()];
    if let Some(port) = config.public_base_url.port() {
        allowed.push(format!("{base}:{port}"));
    } else if config.public_base_url.scheme() == "https" {
        allowed.push(format!("{base}:443"));
    } else if config.public_base_url.scheme() == "http" {
        allowed.push(format!("{base}:80"));
    }
    allowed.iter().any(|candidate| candidate == origin)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use clap::Parser;

    use super::*;
    use crate::config::Cli;

    fn clear_env() {
        for key in [
            "SECURITY_MCP_PUBLIC_BASE_URL",
            "SECURITY_MCP_OAUTH_ENABLED",
            "SECURITY_MCP_CONNECTOR_TOKEN",
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn protocol_version_header_validation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2025-06-18"),
        );
        assert!(validate_mcp_protocol_header(&headers).is_ok());

        headers.insert(
            "MCP-Protocol-Version",
            HeaderValue::from_static("2024-11-05"),
        );
        assert!(validate_mcp_protocol_header(&headers).is_err());
    }

    #[test]
    fn origin_validation_matches_public_base() {
        clear_env();
        unsafe {
            std::env::set_var("SECURITY_MCP_OAUTH_ENABLED", "false");
        }
        let mut config = crate::config::Config::from_sources(Cli::parse_from(["app"])).expect("cfg");
        config.public_base_url = url::Url::parse("https://mcp.example.com").expect("url");
        let mut headers = HeaderMap::new();
        headers.insert(
            "origin",
            HeaderValue::from_static("https://mcp.example.com"),
        );
        assert!(valid_origin(&headers, &config));

        headers.insert(
            "origin",
            HeaderValue::from_static("https://evil.example.com"),
        );
        assert!(!valid_origin(&headers, &config));
    }
}
