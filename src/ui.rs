use std::sync::Arc;

use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::Deserialize;

use crate::auth::{AuthIdentity, AuthLayer};
use crate::modules::{security_investigate, security_tool_catalog};
use crate::oauth;
use crate::types::{AppState, InvestigationInput, ToolCatalogInput};

#[derive(Deserialize)]
struct CacheQuery {
    limit: Option<i64>,
}

pub fn router(state: Arc<AppState>, auth_layer: AuthLayer) -> Router {
    let public_routes = Router::new()
        .route("/health", get(health))
        .merge(oauth::router(state.clone(), auth_layer.clone()));

    let mut protected = Router::new()
        .route("/", get(index).post(run_investigation))
        .route("/tools", get(tools))
        .route("/sources", get(sources))
        .route("/cache", get(cache))
        .route("/cache/clear", post(cache_clear))
        .route("/cache/delete/{key}", post(cache_delete))
        .route("/audit", get(audit))
        .route("/settings", get(settings))
        .with_state(state.clone());

    if state.config.ui_localhost_only {
        protected = protected.layer(middleware::from_fn(enforce_local_ui_only));
    }

    public_routes.merge(auth_layer.protect(protected))
}

async fn enforce_local_ui_only(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if addr.ip().is_loopback() {
        return next.run(req).await;
    }
    (
        StatusCode::FORBIDDEN,
        "web ui is localhost-only and cannot be accessed remotely",
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status":"ok"}))
}

async fn index() -> Html<String> {
    Html(render_page(
        "Security MCP",
        r#"<h1>Security MCP</h1>
<form method="post" action="/">
<label>Target <input name="target" required /></label>
<label>Target Type <select name="target_type"><option value="">auto</option><option value="cve">cve</option><option value="ip">ip</option><option value="domain">domain</option><option value="url">url</option><option value="hash">hash</option></select></label>
<label>Mode <input name="mode" value="auto" /></label>
<label>Depth <select name="depth"><option>quick</option><option selected>standard</option><option>deep</option></select></label>
<label>Output <select name="output_mode"><option value="summary">summary</option><option value="evidence">evidence</option><option value="raw">raw</option></select></label>
<button type="submit">Run</button>
</form>"#,
    ))
}

async fn run_investigation(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<AuthIdentity>,
    Form(input): Form<InvestigationInput>,
) -> Response {
    match security_investigate(&state, input, &identity).await {
        Ok(result) => {
            let findings = result
                .findings
                .iter()
                .map(|f| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&f.severity),
                        html_escape(&f.confidence),
                        html_escape(&f.title),
                        html_escape(&f.source)
                    )
                })
                .collect::<Vec<_>>()
                .join("");

            let sources = result
                .sources
                .iter()
                .map(|s| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        html_escape(&s.name),
                        html_escape(&s.status),
                        html_escape(&s.queried_at.to_rfc3339())
                    )
                })
                .collect::<Vec<_>>()
                .join("");

            let body = format!(
                "<h1>Investigation Result</h1>\
                <p><strong>Target:</strong> {}</p>\
                <p><strong>Summary:</strong> {}</p>\
                <p><strong>Risk:</strong> {} ({})</p>\
                <h2>Findings</h2>\
                <table><thead><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Source</th></tr></thead><tbody>{}</tbody></table>\
                <h2>Sources</h2>\
                <table><thead><tr><th>Source</th><th>Status</th><th>Queried At</th></tr></thead><tbody>{}</tbody></table>\
                <details><summary>Raw JSON</summary><pre>{}</pre></details>\
                <p><a href='/'>Back</a></p>",
                html_escape(&result.target),
                html_escape(&result.summary),
                result.risk.score,
                html_escape(&result.risk.severity),
                findings,
                sources,
                html_escape(
                    &serde_json::to_string_pretty(&result.raw).unwrap_or_else(|_| "{}".to_string())
                )
            );
            Html(render_page("Investigation", &body)).into_response()
        }
        Err(err) => Html(render_page(
            "Investigation Error",
            &format!(
                "<h1>Error</h1><p>{}</p><p><a href='/'>Back</a></p>",
                html_escape(&err.to_string())
            ),
        ))
        .into_response(),
    }
}

async fn tools(State(state): State<Arc<AppState>>) -> Html<String> {
    let catalog = security_tool_catalog(
        &state.registry,
        &state.config,
        ToolCatalogInput {
            category: Some("all".to_string()),
            configured_only: Some(false),
        },
    );
    let rows = catalog["modules"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|m| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(m["id"].as_str().unwrap_or("")),
                html_escape(m["category"].as_str().unwrap_or("")),
                html_escape(m["required_source"].as_str().unwrap_or("none")),
                m["configured"].as_bool().unwrap_or(false),
                html_escape(m["description"].as_str().unwrap_or(""))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    Html(render_page(
        "Tools",
        &format!(
            "<h1>Module Catalog</h1><table><thead><tr><th>ID</th><th>Category</th><th>Required Source</th><th>Configured</th><th>Description</th></tr></thead><tbody>{}</tbody></table>",
            rows
        ),
    ))
}

async fn sources(State(state): State<Arc<AppState>>) -> Html<String> {
    let health = state.db.source_health().await.unwrap_or_default();
    let rows = health
        .iter()
        .map(|s| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(s["source"].as_str().unwrap_or("")),
                html_escape(s["last_success_at"].as_str().unwrap_or("")),
                html_escape(s["last_error_at"].as_str().unwrap_or("")),
                html_escape(s["last_error"].as_str().unwrap_or(""))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    Html(render_page(
        "Sources",
        &format!(
            "<h1>Sources</h1><table><thead><tr><th>Source</th><th>Last Success</th><th>Last Error At</th><th>Last Error</th></tr></thead><tbody>{}</tbody></table>",
            rows
        ),
    ))
}

async fn cache(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CacheQuery>,
) -> Html<String> {
    let entries = state
        .db
        .cache_list(query.limit.unwrap_or(50))
        .await
        .unwrap_or_default();
    let rows = entries
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><form method='post' action='/cache/delete/{}'><button type='submit'>Delete</button></form></td></tr>",
                html_escape(&e.module_id),
                html_escape(&e.target),
                html_escape(&e.created_at.to_rfc3339()),
                html_escape(&e.expires_at.to_rfc3339()),
                html_escape(&e.key)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    Html(render_page(
        "Cache",
        &format!(
            "<h1>Cache</h1><form method='post' action='/cache/clear'><button type='submit'>Clear Cache</button></form><table><thead><tr><th>Module</th><th>Target</th><th>Created</th><th>Expires</th><th>Action</th></tr></thead><tbody>{}</tbody></table>",
            rows
        ),
    ))
}

async fn cache_clear(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state.db.cache_clear().await;
    Redirect::to("/cache")
}

async fn cache_delete(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let _ = state.db.cache_delete(&key).await;
    Redirect::to("/cache")
}

async fn audit(State(state): State<Arc<AppState>>) -> Html<String> {
    let events = state.db.audit_list(100).await.unwrap_or_default();
    let rows = events
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(e["ts"].as_str().unwrap_or("")),
                html_escape(e["tool"].as_str().unwrap_or("")),
                html_escape(e["target"].as_str().unwrap_or("")),
                html_escape(e["status"].as_str().unwrap_or("")),
                html_escape(e["auth_method"].as_str().unwrap_or("")),
                e["duration_ms"].as_i64().unwrap_or(0)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    Html(render_page(
        "Audit",
        &format!(
            "<h1>Audit Events</h1><table><thead><tr><th>Timestamp</th><th>Tool</th><th>Target</th><th>Status</th><th>Auth</th><th>Duration(ms)</th></tr></thead><tbody>{}</tbody></table>",
            rows
        ),
    ))
}

async fn settings(State(state): State<Arc<AppState>>) -> Html<String> {
    let config =
        serde_json::to_string_pretty(&state.config.redacted()).unwrap_or_else(|_| "{}".to_string());
    Html(render_page(
        "Settings",
        &format!(
            "<h1>Effective Configuration</h1><pre>{}</pre>",
            html_escape(&config)
        ),
    ))
}

fn render_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{}</title>\
        <style>body{{font-family:ui-sans-serif,system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:.5rem;text-align:left}}th{{background:#f4f4f4}}form{{display:grid;gap:.7rem;max-width:700px}}label{{display:grid;gap:.2rem}}input,select,button{{padding:.5rem}}</style>\
        </head><body><nav><a href='/'>Investigate</a> | <a href='/tools'>Tools</a> | <a href='/sources'>Sources</a> | <a href='/cache'>Cache</a> | <a href='/audit'>Audit</a> | <a href='/settings'>Settings</a></nav>{}</body></html>",
        html_escape(title),
        body
    )
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn localhost_ui_gate_allows_loopback() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(enforce_local_ui_only))
            .layer(MockConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn localhost_ui_gate_blocks_non_loopback() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(enforce_local_ui_only))
            .layer(MockConnectInfo(std::net::SocketAddr::from((
                [10, 0, 0, 8],
                12345,
            ))));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
