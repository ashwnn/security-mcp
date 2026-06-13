use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::{AuthIdentity, AuthLayer};
use crate::modules::{
    security_classify_hash, security_compare, security_extract_iocs, security_investigate,
    security_investigate_cve, security_investigate_indicator, security_run_tool,
    security_scan_dependencies, security_tool_catalog,
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
        .route("/mcp", get(handle_mcp_get).post(handle_mcp))
        .with_state(state);
    auth_layer.protect(protected)
}

async fn handle_mcp_get() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(http::header::ALLOW, "POST")],
        "server-to-client SSE stream is not implemented; send JSON-RPC requests with POST /mcp",
    )
        .into_response()
}

#[axum::debug_handler]
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

    tracing::info!(
        mcp_method = %request.method,
        auth_method = %identity.method,
        auth_subject = %identity.subject,
        "mcp request"
    );

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
            } else if msg.starts_with("unknown tool") || msg.starts_with("missing tool name") {
                rpc_error(request.id, -32602, &msg)
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
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "security-mcp", "version": env!("CARGO_PKG_VERSION")},
            "protocolVersion": "2025-06-18",
        })),
        "tools/list" | "mcp.list_tools" => {
            require_scope(auth, "mcp:read")?;
            Ok(serde_json::json!({ "tools": mcp_tool_definitions(state) }))
        }
        "tools/call" | "mcp.call_tool" => {
            require_scope(auth, "mcp:tools")?;
            let tool_name = params["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing tool name"))?;
            let args = params["arguments"].clone();
            match call_tool(state, auth, tool_name, args).await {
                Ok(structured) => Ok(tool_success(structured)),
                Err(err) if err.to_string().starts_with("unknown tool") => Err(err),
                Err(err) => Ok(tool_execution_error(&err.to_string())),
            }
        }
        _ => Err(anyhow::anyhow!("method not found")),
    }
}

fn require_scope(auth: &AuthIdentity, scope: &str) -> anyhow::Result<()> {
    if auth.scopes.iter().any(|granted| granted == scope) {
        return Ok(());
    }
    Err(anyhow::anyhow!("insufficient scope: {scope} required"))
}

async fn call_tool(
    state: &AppState,
    auth: &AuthIdentity,
    tool_name: &str,
    args: Value,
) -> anyhow::Result<Value> {
    tracing::info!(
        tool = %tool_name,
        auth_method = %auth.method,
        auth_subject = %auth.subject,
        "mcp tool call"
    );
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
        "security_extract_iocs" => {
            let text = args["text"].as_str().unwrap_or("");
            Ok(serde_json::to_value(security_extract_iocs(text).await?)?)
        }
        "security_classify_hash" => {
            let hash = args["hash"].as_str().unwrap_or("");
            Ok(serde_json::to_value(security_classify_hash(hash).await?)?)
        }
        _ => Err(anyhow::anyhow!("unknown tool: {tool_name}")),
    }
}

fn tool_success(structured: Value) -> Value {
    let text = serde_json::to_string_pretty(&structured).unwrap_or_else(|_| "{}".to_string());
    serde_json::json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": false,
    })
}

fn tool_execution_error(message: &str) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": message}],
        "isError": true,
    })
}

fn mcp_tool_definitions(state: &AppState) -> Vec<Value> {
    let mut tools = vec![
        tool(
            "security_investigate",
            "Security Investigation",
            "Run a passive security enrichment workflow for a CVE, public IP, domain, URL, or hash. Use for defensive triage and exposure context only.",
            investigation_schema(),
        ),
        tool(
            "security_investigate_cve",
            "CVE Investigation",
            "Enrich a CVE with NVD, EPSS, CISA KEV, reference, PoC-signal, and ATT&CK mapping context where available.",
            cve_schema(),
        ),
        tool(
            "security_investigate_indicator",
            "Indicator Investigation",
            "Investigate a public indicator such as an IP, domain, URL, or file hash using configured reputation and passive-intelligence sources.",
            indicator_schema(),
        ),
        tool(
            "security_scan_dependencies",
            "Dependency Vulnerability Scan",
            "Check supplied packages or dependency file contents against OSV and GitHub advisory data where configured.",
            dependency_schema(),
        ),
        tool(
            "security_compare",
            "Security Comparison",
            "Compare a small set of security items and return an ordered risk-oriented comparison. Current scoring is heuristic.",
            compare_schema(),
        ),
        tool(
            "security_tool_catalog",
            "Security Source Catalog",
            "List available internal modules, source requirements, and configuration status.",
            catalog_schema(),
        ),
        tool(
            "security_extract_iocs",
            "Extract IOCs",
            "Extract IPs, domains, URLs, hashes, CVEs, and emails from analyst text without calling external sources.",
            extract_iocs_schema(),
        ),
        tool(
            "security_classify_hash",
            "Classify Hash",
            "Classify a hash string by format and likely algorithm without calling external sources.",
            classify_hash_schema(),
        ),
    ];

    if state.config.expert_tool_enabled {
        tools.push(tool(
            "security_run_tool",
            "Run Internal Security Module",
            "Run one internal module by ID. Disabled by default and requires mcp:raw or mcp:admin scope.",
            run_tool_schema(),
        ));
    }

    tools
}

fn tool(name: &str, title: &str, description: &str, input_schema: Value) -> Value {
    serde_json::json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": true,
            "destructiveHint": false,
            "idempotentHint": true,
            "openWorldHint": true,
        }
    })
}

fn output_mode_schema() -> Value {
    serde_json::json!({
        "type": "string",
        "enum": ["summary", "evidence", "raw"],
        "description": "summary omits raw source payloads, evidence includes normalized evidence, raw requires mcp:raw or mcp:admin scope"
    })
}

fn investigation_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "target": {"type": "string", "minLength": 1, "description": "CVE ID, public IP, domain, URL, package reference, or file hash"},
            "target_type": {"type": "string", "enum": ["cve", "ip", "domain", "url", "hash", "package", "auto"], "description": "Optional explicit target type. Omit or use auto for detection."},
            "mode": {"type": "string", "enum": ["auto", "passive_only", "active_http_headers", "threat_intel"], "description": "Requested investigation mode. Unsupported modes may be treated conservatively."},
            "depth": {"type": "string", "enum": ["quick", "standard", "deep"], "description": "Requested source breadth."},
            "sources": {"type": "array", "items": {"type": "string"}, "description": "Optional source/module preference list."},
            "output_mode": output_mode_schema()
        },
        "required": ["target"],
        "additionalProperties": false
    })
}

fn cve_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "cve_id": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
            "include_epss": {"type": "boolean", "default": true},
            "include_kev": {"type": "boolean", "default": true},
            "include_poc": {"type": "boolean", "default": true},
            "include_mitre": {"type": "boolean", "default": true},
            "include_vendor_advisories": {"type": "boolean", "default": true},
            "output_mode": output_mode_schema()
        },
        "required": ["cve_id"],
        "additionalProperties": false
    })
}

fn indicator_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "indicator": {"type": "string", "minLength": 1},
            "indicator_type": {"type": "string", "enum": ["ip", "domain", "url", "hash", "auto"]},
            "include_reputation": {"type": "boolean", "default": true},
            "include_passive_dns": {"type": "boolean", "default": true},
            "include_malware": {"type": "boolean", "default": true},
            "include_url_safety": {"type": "boolean", "default": true},
            "output_mode": output_mode_schema()
        },
        "required": ["indicator"],
        "additionalProperties": false
    })
}

fn dependency_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "ecosystem": {"type": "string", "description": "OSV ecosystem such as PyPI, npm, Go, crates.io, Maven, NuGet, or auto"},
            "packages": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "version": {"type": "string"}}, "required": ["name"], "additionalProperties": false}},
            "file_type": {"type": "string", "enum": ["requirements.txt", "package.json", "poetry.lock", "go.mod", "Cargo.toml"]},
            "file_content": {"type": "string"},
            "output_mode": output_mode_schema()
        },
        "additionalProperties": false
    })
}

fn compare_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 25},
            "comparison_type": {"type": "string", "enum": ["risk", "exposure", "priority"]},
            "output_mode": output_mode_schema()
        },
        "required": ["items"],
        "additionalProperties": false
    })
}

fn catalog_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "category": {"type": "string", "description": "Module category or all"},
            "configured_only": {"type": "boolean", "default": false}
        },
        "additionalProperties": false
    })
}

fn extract_iocs_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Analyst note, alert body, log excerpt, or ticket text to parse for indicators"}
        },
        "required": ["text"],
        "additionalProperties": false
    })
}

fn classify_hash_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "hash": {"type": "string", "description": "MD5, SHA1, SHA256, or SHA512 hexadecimal hash"}
        },
        "required": ["hash"],
        "additionalProperties": false
    })
}

fn run_tool_schema() -> Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "tool_id": {"type": "string"},
            "args": {"type": "object"},
            "output_mode": output_mode_schema()
        },
        "required": ["tool_id", "args"],
        "additionalProperties": false
    })
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
    let supported = ["2025-03-26", "2025-06-18"];
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
        let mut config =
            crate::config::Config::from_sources(Cli::parse_from(["app"])).expect("cfg");
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
