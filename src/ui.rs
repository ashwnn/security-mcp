use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
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

#[derive(Deserialize)]
struct ToolsQuery {
    category: Option<String>,
    configured_only: Option<bool>,
}

#[derive(Deserialize)]
struct SettingsQuery {
    message: Option<String>,
}

#[derive(Deserialize)]
struct SettingsSaveForm {
    bearer_token: Option<String>,
    api_key: Option<String>,
    connector_token: Option<String>,
    oauth_enabled: Option<String>,
    public_mode: Option<String>,
    api_key_query_enabled: Option<String>,
}

#[derive(Copy, Clone)]
enum TokenKind {
    Bearer,
    ApiKey,
    Connector,
}

pub fn router(state: Arc<AppState>, auth_layer: AuthLayer) -> Router {
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/favicon.svg", get(favicon_svg))
        .route("/assets/ui.js", get(ui_script))
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
        .route("/settings/save", post(settings_save))
        .route("/settings/generate-auth", post(settings_generate_auth))
        .route("/settings/token/{kind}/copy", post(settings_token_copy))
        .route(
            "/settings/token/{kind}/regenerate",
            post(settings_token_regenerate),
        )
        .with_state(state.clone());

    if state.config.ui_localhost_only {
        protected = protected
            .layer(middleware::from_fn_with_state(
                state.clone(),
                enforce_same_origin_ui_mutation,
            ))
            .layer(middleware::from_fn(enforce_local_ui_only));
        return public_routes.merge(protected);
    }

    protected = protected.layer(middleware::from_fn_with_state(
        state.clone(),
        enforce_same_origin_ui_mutation,
    ));
    public_routes.merge(auth_layer.protect(protected))
}

async fn enforce_local_ui_only(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if addr.ip().is_loopback() && local_ui_host_allowed(req.headers()) {
        return next.run(req).await;
    }
    (
        StatusCode::FORBIDDEN,
        "web ui is localhost-only and cannot be accessed remotely",
    )
        .into_response()
}

fn local_ui_host_allowed(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = host.parse::<http::uri::Authority>() else {
        return false;
    };
    let host = authority.host().trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

async fn enforce_same_origin_ui_mutation(
    State(_state): State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS)
        || has_same_origin(&req)
    {
        return next.run(req).await;
    }
    (StatusCode::FORBIDDEN, "cross-origin UI request rejected").into_response()
}

fn has_same_origin(req: &Request<axum::body::Body>) -> bool {
    let headers = req.headers();
    let Some(origin) = headers.get("origin") else {
        return !header_equals(headers, "sec-fetch-site", "cross-site");
    };
    let Ok(origin) = origin
        .to_str()
        .ok()
        .and_then(|value| url::Url::parse(value).ok())
        .ok_or(())
    else {
        return false;
    };
    let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(expected) = url::Url::parse(&format!("{}://{host}", origin.scheme())) else {
        return false;
    };
    origin.host_str() == expected.host_str()
        && origin.port_or_known_default() == expected.port_or_known_default()
}

fn header_equals(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status":"ok"}))
}

async fn index() -> Html<String> {
    Html(render_page(
        "Security MCP",
        r#"<section class='panel'>
<h2>Investigation</h2>
<form method="post" action="/">
<label>Target <input name="target" placeholder="CVE-2024-3094, example.com, 1.1.1.1, https://..." required /></label>
<label>Target Type
  <select name="target_type">
    <option value="">auto</option>
    <option value="cve">cve</option>
    <option value="ip">ip</option>
    <option value="domain">domain</option>
    <option value="url">url</option>
    <option value="hash">hash</option>
  </select>
</label>
<div class='grid-2'>
  <label>Mode <input name="mode" value="auto" /></label>
  <label>Depth
    <select name="depth">
      <option value="quick">quick</option>
      <option value="standard" selected>standard</option>
      <option value="deep">deep</option>
    </select>
  </label>
</div>
<label>Output
  <select name="output_mode">
    <option value="summary" selected>summary</option>
    <option value="evidence">evidence</option>
    <option value="raw">raw</option>
  </select>
</label>
<fieldset>
  <legend>Preferred Sources (optional)</legend>
  <label class='inline'><input type='checkbox' name='sources' value='nvd' /> NVD</label>
  <label class='inline'><input type='checkbox' name='sources' value='epss' /> EPSS</label>
  <label class='inline'><input type='checkbox' name='sources' value='cisa_kev' /> CISA KEV</label>
  <label class='inline'><input type='checkbox' name='sources' value='shodan' /> Shodan</label>
  <label class='inline'><input type='checkbox' name='sources' value='virustotal' /> VirusTotal</label>
</fieldset>
<button type="submit">Run Investigation</button>
</form>
</section>"#,
    ))
}

async fn run_investigation(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Form(input): Form<InvestigationInput>,
) -> Response {
    let identity = identity
        .map(|Extension(value)| value)
        .unwrap_or_else(local_ui_identity);

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
            let findings = if findings.is_empty() {
                "<tr><td colspan='4' class='empty'>No findings.</td></tr>".to_string()
            } else {
                findings
            };

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
            let sources = if sources.is_empty() {
                "<tr><td colspan='3' class='empty'>No source status rows.</td></tr>".to_string()
            } else {
                sources
            };

            let body = format!(
                "<section class='panel'><h1>Investigation Result</h1>\
                <p><strong>Target:</strong> {}</p>\
                <p><strong>Type:</strong> {}</p>\
                <p><strong>Summary:</strong> {}</p>\
                <p><strong>Risk:</strong> <span class='badge badge-{}'>{}</span> ({})</p></section>\
                <section class='panel'><h2>Findings</h2>\
                <table><thead><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Source</th></tr></thead><tbody>{}</tbody></table>\
                </section>\
                <section class='panel'><h2>Sources</h2>\
                <table><thead><tr><th>Source</th><th>Status</th><th>Queried At</th></tr></thead><tbody>{}</tbody></table>\
                </section>\
                <section class='panel'>\
                <details><summary>Raw JSON</summary><pre>{}</pre></details>\
                <p><a href='/' class='button button-outline'>Run Another</a></p></section>",
                html_escape(&result.target),
                html_escape(&result.target_type),
                html_escape(&result.summary),
                html_escape(&result.risk.severity),
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

async fn tools(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ToolsQuery>,
) -> Html<String> {
    let category = query.category.clone().unwrap_or_else(|| "all".to_string());
    let configured_only = query.configured_only.unwrap_or(false);
    let catalog = security_tool_catalog(
        &state.registry,
        &state.config,
        ToolCatalogInput {
            category: Some(category.clone()),
            configured_only: Some(configured_only),
        },
    );

    let mut categories = BTreeSet::new();
    for module in state.registry.list() {
        categories.insert(module.category);
    }
    let category_options = categories
        .into_iter()
        .map(|item| {
            let selected = if item == category { "selected" } else { "" };
            format!(
                "<option value='{}' {}>{}</option>",
                html_escape(&item),
                selected,
                html_escape(&item)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    let rows = catalog["modules"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|m| {
            let configured = if m["configured"].as_bool().unwrap_or(false) {
                "<span class='badge badge-ok'>configured</span>"
            } else {
                "<span class='badge badge-warn'>missing</span>"
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                html_escape(m["id"].as_str().unwrap_or("")),
                html_escape(m["category"].as_str().unwrap_or("")),
                html_escape(m["required_source"].as_str().unwrap_or("none")),
                configured,
                html_escape(m["description"].as_str().unwrap_or(""))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rows = if rows.is_empty() {
        "<tr><td colspan='5' class='empty'>No modules match the current filter.</td></tr>"
            .to_string()
    } else {
        rows
    };
    Html(render_page(
        "Tools",
        &format!(
            "<section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h1>Module Catalog</h1>\
                  <p class='section-kicker'>Filter modules by category and configuration.</p>\
                </div>\
                <form method='get' action='/tools' class='toolbar'>\
                  <label>Category\
                    <select name='category'><option value='all'>all</option>{}</select>\
                  </label>\
                  <label class='inline'><input type='checkbox' name='configured_only' value='true' {} /> configured only</label>\
                  <button type='submit' class='button button-outline button-icon'>{} <span>Apply filters</span></button>\
                </form>\
              </div>\
              <p class='section-count'><strong>{}</strong> modules shown</p>\
              <table><thead><tr><th>ID</th><th>Category</th><th>Required Source</th><th>Configured</th><th>Description</th></tr></thead><tbody>{}</tbody></table></section>",
            category_options,
            if configured_only { "checked" } else { "" },
            filter_icon(),
            catalog["modules"].as_array().map(|m| m.len()).unwrap_or(0),
            rows
        ),
    ))
}

async fn sources(State(state): State<Arc<AppState>>) -> Html<String> {
    let health_rows = state.db.source_health().await.unwrap_or_default();
    let mut health_map = BTreeMap::new();
    for row in health_rows {
        let name = row["source"].as_str().unwrap_or("").to_string();
        health_map.insert(name, row);
    }

    let mut sources = BTreeSet::new();
    for module in state.registry.list() {
        if let Some(required) = module.required_source {
            sources.insert(required);
        }
    }

    let rows = sources
        .into_iter()
        .map(|source| {
            let configured = if state.config.source_configured(&source) {
                "<span class='badge badge-ok'>configured</span>"
            } else {
                "<span class='badge badge-warn'>missing</span>"
            };
            let health = health_map.get(&source);
            let website = source_website_url(&source)
                .map(|url| {
                    format!(
                        "<a class='source-link' href='{}' target='_blank' rel='noreferrer noopener'>{} <span>{}</span></a>",
                        html_escape(url),
                        external_icon(),
                        html_escape(&source)
                    )
                })
                .unwrap_or_else(|| html_escape(&source));
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                website,
                configured,
                html_escape(
                    health
                        .and_then(|h| h["last_success_at"].as_str())
                        .unwrap_or("never")
                ),
                html_escape(health.and_then(|h| h["last_error"].as_str()).unwrap_or("")),
                required_env_for_source(&source)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let rows = if rows.is_empty() {
        "<tr><td colspan='5' class='empty'>No source mappings available.</td></tr>".to_string()
    } else {
        rows
    };
    Html(render_page(
        "Sources",
        &format!(
            "<section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h1>Sources</h1>\
                  <p class='section-kicker'>Each source name links to its official home or documentation.</p>\
                </div>\
              </div>\
              <table><thead><tr><th>Source</th><th>Configured</th><th>Last Success</th><th>Last Error</th><th>Required Env</th></tr></thead><tbody>{}</tbody></table></section>",
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
    let rows = if rows.is_empty() {
        "<tr><td colspan='5' class='empty'>Cache is empty.</td></tr>".to_string()
    } else {
        rows
    };
    Html(render_page(
        "Cache",
        &format!(
            "<section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h1>Cache</h1>\
                  <p class='section-kicker'>Stored investigations and manual cleanup.</p>\
                </div>\
                <div class='section-actions'>\
                  <span class='badge badge-low'>{} entries</span>\
                  <form method='post' action='/cache/clear'>\
                  <button type='submit' class='button button-outline button-icon'>{} <span>Clear Cache</span></button>\
                  </form>\
                </div>\
              </div>\
              <table><thead><tr><th>Module</th><th>Target</th><th>Created</th><th>Expires</th><th>Action</th></tr></thead><tbody>{}</tbody></table></section>",
            entries.len(),
            refresh_icon(),
            rows
        ),
    ))
}

async fn cache_clear(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let _ = state.db.cache_clear().await;
    Redirect::to("/cache").into_response()
}

async fn cache_delete(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(key): Path<String>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let _ = state.db.cache_delete(&key).await;
    Redirect::to("/cache").into_response()
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
    let rows = if rows.is_empty() {
        "<tr><td colspan='6' class='empty'>No audit events yet.</td></tr>".to_string()
    } else {
        rows
    };
    Html(render_page(
        "Audit",
        &format!(
            "<section class='panel'><h1>Audit Events</h1><table><thead><tr><th>Timestamp</th><th>Tool</th><th>Target</th><th>Status</th><th>Auth</th><th>Duration(ms)</th></tr></thead><tbody>{}</tbody></table></section>",
            rows
        ),
    ))
}

async fn settings(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Query(query): Query<SettingsQuery>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let config =
        serde_json::to_string_pretty(&state.config.redacted()).unwrap_or_else(|_| "{}".to_string());
    let token_cards = [
        token_card(TokenKind::Bearer, state.config.bearer_token.as_deref()),
        token_card(TokenKind::ApiKey, state.config.api_key.as_deref()),
        token_card(
            TokenKind::Connector,
            state.config.connector_token.as_deref(),
        ),
    ]
    .join("");
    let auth_summary = serde_json::json!({
        "bearer_token_configured": state.config.bearer_token.is_some(),
        "api_key_configured": state.config.api_key.is_some(),
        "connector_token_configured": state.config.connector_token.is_some(),
        "SECURITY_MCP_BEARER_SCOPES": state.config.bearer_scopes,
        "SECURITY_MCP_API_KEY_SCOPES": state.config.api_key_scopes,
        "SECURITY_MCP_OAUTH_ALLOWED_SCOPES": state.config.oauth_allowed_scopes,
        "SECURITY_MCP_OAUTH_DEFAULT_SCOPES": state.config.oauth_default_scopes,
        "SECURITY_MCP_API_KEY_HEADER": state.config.api_key_header,
        "SECURITY_MCP_API_KEY_QUERY_ENABLED": state.config.api_key_query_enabled,
        "SECURITY_MCP_API_KEY_QUERY_NAME": state.config.api_key_query_name,
        "SECURITY_MCP_OAUTH_ENABLED": state.config.oauth_enabled,
        "SECURITY_MCP_PUBLIC_MODE": state.config.public_mode
    });
    let auth_summary = serde_json::to_string_pretty(&auth_summary).unwrap_or_default();
    let message = query
        .message
        .as_deref()
        .map(|m| format!("<p class='note'>{}</p>", html_escape(m)))
        .unwrap_or_default();
    Html(render_page(
        "Settings",
        &format!(
            "<section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h1>Settings</h1>\
                  <p class='section-kicker'>Active secrets stay hidden. Persisted token changes require a restart before they become active.</p>\
                </div>\
              </div>\
              {}\
              <div class='secret-grid'>{}</div>\
            </section>\
            <section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h2>Auth configuration</h2>\
                  <p class='section-kicker'>Persist auth flags here, then restart the server to apply them.</p>\
                </div>\
              </div>\
              <form method='post' action='/settings/save'>\
                <div class='grid-2'>\
                  <label>Bearer token <input name='bearer_token' placeholder='set or replace token' /></label>\
                  <label>API key <input name='api_key' placeholder='set or replace key' /></label>\
                </div>\
                <label>OAuth connector token <input name='connector_token' placeholder='set or replace connector token' /></label>\
                <div class='settings-flags'>\
                  <label class='inline'><input type='checkbox' name='oauth_enabled' value='true' {} /> OAuth enabled</label>\
                  <label class='inline'><input type='checkbox' name='public_mode' value='true' {} /> Public mode enabled</label>\
                  <label class='inline'><input type='checkbox' name='api_key_query_enabled' value='true' {} /> API key query enabled</label>\
              </div>\
              <button type='submit' class='button'>Save auth settings</button>\
            </form>\
            </section>\
            <section class='panel'>\
              <div class='section-head'>\
                <div>\
                  <h2>Rotate all</h2>\
                  <p class='section-kicker'>Bulk-rotate all three tokens when you want a clean slate.</p>\
                </div>\
                <form method='post' action='/settings/generate-auth'>\
                  <button type='submit' class='button button-outline button-icon'>{} <span>Rotate all tokens</span></button>\
                </form>\
              </div>\
            </section>\
            <section class='panel'><h2>Effective auth values</h2><pre>{}</pre></section>\
            <section class='panel'><h2>Effective configuration</h2><pre>{}</pre></section>",
            message,
            token_cards,
            if state.config.oauth_enabled {
                "checked"
            } else {
                ""
            },
            if state.config.public_mode {
                "checked"
            } else {
                ""
            },
            if state.config.api_key_query_enabled {
                "checked"
            } else {
                ""
            },
            refresh_icon(),
            auth_summary,
            html_escape(&config),
        ),
    );
    ([(http::header::CACHE_CONTROL, "no-store, private")], Html(html_body)).into_response()
}

async fn settings_save(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Form(form): Form<SettingsSaveForm>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let mut updates = Vec::new();
    if let Some(token) = form.bearer_token.filter(|v| !v.trim().is_empty()) {
        updates.push(("SECURITY_MCP_BEARER_TOKEN".to_string(), token));
    }
    if let Some(key) = form.api_key.filter(|v| !v.trim().is_empty()) {
        updates.push(("SECURITY_MCP_API_KEY".to_string(), key));
    }
    if let Some(token) = form.connector_token.filter(|v| !v.trim().is_empty()) {
        updates.push(("SECURITY_MCP_CONNECTOR_TOKEN".to_string(), token));
    }
    updates.push((
        "SECURITY_MCP_OAUTH_ENABLED".to_string(),
        checkbox_to_bool(form.oauth_enabled).to_string(),
    ));
    updates.push((
        "SECURITY_MCP_PUBLIC_MODE".to_string(),
        checkbox_to_bool(form.public_mode).to_string(),
    ));
    updates.push((
        "SECURITY_MCP_API_KEY_QUERY_ENABLED".to_string(),
        checkbox_to_bool(form.api_key_query_enabled).to_string(),
    ));

    let result =
        apply_env_updates(&updates).map(|_| "settings saved to .env; restart required".to_string());
    let message = match result {
        Ok(msg) => msg,
        Err(err) => format!("failed to write .env: {err}"),
    };
    Redirect::to(&format!(
        "/settings?message={}",
        urlencoding::encode(&message)
    ))
    .into_response()
}

async fn settings_generate_auth(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let bearer = random_hex_token(32);
    let api_key = random_hex_token(32);
    let connector = random_hex_token(32);

    let updates = token_rotation_updates(&[
        (TokenKind::Bearer, bearer.clone()),
        (TokenKind::ApiKey, api_key.clone()),
        (TokenKind::Connector, connector.clone()),
    ]);

    let write_result = apply_env_updates(&updates);
    match write_result {
        Ok(_) => token_rotation_response(&[
            (TokenKind::Bearer, bearer),
            (TokenKind::ApiKey, api_key),
            (TokenKind::Connector, connector),
        ]),
        Err(err) => Html(render_page(
            "Token Rotation Failed",
            &format!(
                "<section class='panel'><h1>Token Rotation Failed</h1><p class='note'>{}</p></section>",
                html_escape(&format!("failed to write .env: {err}"))
            ),
        ))
        .into_response(),
    }
}

async fn settings_token_copy(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(kind): Path<String>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let Some(kind) = token_kind_from_slug(&kind) else {
        return (StatusCode::NOT_FOUND, "unknown token kind").into_response();
    };
    let Some(value) = token_kind_current(kind, &state) else {
        return (StatusCode::NOT_FOUND, "token not configured").into_response();
    };
    (
        StatusCode::OK,
        [(http::header::CACHE_CONTROL, "no-store")],
        value.to_string(),
    )
        .into_response()
}

async fn settings_token_regenerate(
    State(state): State<Arc<AppState>>,
    identity: Option<Extension<AuthIdentity>>,
    Path(kind): Path<String>,
) -> Response {
    if !remote_admin_allowed(&state, identity.as_ref().map(|v| &v.0)) {
        return admin_scope_required();
    }
    let Some(kind) = token_kind_from_slug(&kind) else {
        return (StatusCode::NOT_FOUND, "unknown token kind".to_string()).into_response();
    };

    let token = random_hex_token(32);
    let updates = token_rotation_updates(&[(kind, token.clone())]);
    match apply_env_updates(&updates) {
        Ok(_) => token_rotation_response(&[(kind, token)]),
        Err(err) => Redirect::to(&format!(
            "/settings?message={}",
            urlencoding::encode(&format!(
                "failed to rotate {}: {err}",
                token_kind_label(kind)
            ))
        ))
        .into_response(),
    }
}

fn remote_admin_allowed(state: &AppState, identity: Option<&AuthIdentity>) -> bool {
    state.config.ui_localhost_only
        || identity.is_some_and(|identity| identity.scopes.iter().any(|scope| scope == "mcp:admin"))
}

fn admin_scope_required() -> Response {
    (StatusCode::FORBIDDEN, "mcp:admin scope required").into_response()
}

fn token_rotation_response(tokens: &[(TokenKind, String)]) -> Response {
    let rows = tokens
        .iter()
        .map(|(kind, value)| {
            format!(
                "<label>{}<input readonly value='{}' /></label>",
                html_escape(token_kind_label(*kind)),
                html_escape(value)
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let body = format!(
        "<section class='panel'><h1>Generated Tokens</h1>\
        <p class='note'>Copy these replacement values now. They are written to .env and become active after restart.</p>\
        <div class='secret-grid'>{rows}</div>\
        <p><a class='button button-outline' href='/settings'>Back to Settings</a></p>\
        </section>"
    );
    (
        [(http::header::CACHE_CONTROL, "no-store")],
        Html(render_page("Generated Tokens", &body)),
    )
        .into_response()
}

fn token_rotation_updates(tokens: &[(TokenKind, String)]) -> Vec<(String, String)> {
    let mut updates: Vec<(String, String)> = tokens
        .iter()
        .map(|(kind, value)| (token_kind_env_key(*kind).to_string(), value.clone()))
        .collect();

    updates.push((
        "SECURITY_MCP_BEARER_SCOPES".to_string(),
        "mcp:read,mcp:tools".to_string(),
    ));
    updates.push((
        "SECURITY_MCP_API_KEY_SCOPES".to_string(),
        "mcp:read,mcp:tools".to_string(),
    ));
    updates.push((
        "SECURITY_MCP_OAUTH_ALLOWED_SCOPES".to_string(),
        "mcp:read,mcp:tools,mcp:raw,mcp:admin".to_string(),
    ));
    updates.push((
        "SECURITY_MCP_OAUTH_DEFAULT_SCOPES".to_string(),
        "mcp:read,mcp:tools".to_string(),
    ));

    updates
}

fn render_page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{}</title>\
        <link rel='icon' type='image/svg+xml' href='{}'>\
        <script defer src='/assets/ui.js'></script>\
        <style>\
        :root{{--surface:rgba(255,255,255,.95);--bg:#f4f5f7;--bg-accent:#edf0f4;--ink:#0f172a;--muted:#5b6472;--line:#d6dde7;--shadow:0 14px 34px rgba(15,23,42,.08);--ok:#0f766e;--warn:#b45309;--high:#b91c1c;--focus:#1d4ed8;}}\
        *{{box-sizing:border-box;}}\
        html{{scroll-behavior:smooth;}}\
        body{{margin:0;min-height:100vh;background:radial-gradient(circle at top right, var(--bg-accent), transparent 36%), linear-gradient(180deg, #ffffff 0%, var(--bg) 100%);color:var(--ink);font:400 15.5px/1.55 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;}}\
        a{{color:inherit;}}\
        .wrap{{max-width:86rem;margin:0 auto;padding:1.1rem;}}\
        .topbar{{position:sticky;top:1rem;z-index:10;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;padding:.95rem 1rem;border:1px solid rgba(214,221,231,.95);background:var(--surface);border-radius:1rem;margin-bottom:1rem;box-shadow:var(--shadow);}}\
        .topbar strong{{font-size:1.02rem;letter-spacing:.02em;}}\
        .nav{{display:flex;align-items:center;gap:.35rem;flex-wrap:wrap;}}\
        .nav a{{padding:.5rem .82rem;border:1px solid transparent;border-radius:999px;text-decoration:none;color:var(--muted);font-weight:600;transition:background .15s ease,border-color .15s ease,color .15s ease,transform .15s ease;}}\
        .nav a:hover{{background:#fff;border-color:var(--line);color:var(--ink);transform:translateY(-1px);}}\
        .panel{{border:1px solid rgba(214,221,231,.95);background:var(--surface);border-radius:1rem;padding:1.15rem 1.25rem;margin-bottom:.95rem;box-shadow:var(--shadow);}}\
        .panel h1,.panel h2,.panel h3{{margin-top:0;}}\
        .section-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;}}\
        .section-kicker{{margin:.2rem 0 0;color:var(--muted);font-size:.95rem;}}\
        .section-count{{margin:.1rem 0 .8rem;color:var(--muted);}}\
        .section-actions{{display:flex;align-items:center;gap:.65rem;flex-wrap:wrap;}}\
        form{{display:grid;gap:.95rem;}}\
        label{{display:grid;gap:.35rem;font-weight:600;}}\
        input,select,textarea{{width:100%;border:1px solid var(--line);border-radius:.75rem;padding:.68rem .85rem;background:#fff;color:var(--ink);font:inherit;box-shadow:inset 0 1px 2px rgba(15,23,42,.03);transition:border-color .15s ease,box-shadow .15s ease,transform .15s ease;}}\
        input:focus,select:focus,textarea:focus{{outline:none;border-color:var(--focus);box-shadow:0 0 0 3px rgba(29,78,216,.14);}}\
        button,.button{{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;padding:.68rem .98rem;border:1px solid var(--ink);border-radius:.75rem;background:var(--ink);color:#fff;font:600 .98rem/1 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;text-decoration:none;cursor:pointer;transition:transform .15s ease,box-shadow .15s ease,background .15s ease,border-color .15s ease;}}\
        button:hover,.button:hover{{transform:translateY(-1px);box-shadow:0 10px 20px rgba(15,23,42,.12);}}\
        .button-outline{{background:#fff;color:var(--ink);border-color:var(--line);}}\
        .button-outline:hover{{background:#f8fafc;}}\
        .button-icon svg{{flex:0 0 auto;}}\
        button:focus-visible,.button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{{outline:none;box-shadow:0 0 0 3px rgba(29,78,216,.2);}}\
        fieldset{{border:1px solid var(--line);border-radius:.9rem;padding:1rem 1.1rem;background:#fff;}}\
        legend{{padding:0 .35rem;font-weight:600;color:var(--muted);}}\
        .grid-2{{display:grid;grid-template-columns:1fr;gap:.95rem;}}\
        .toolbar{{display:flex;align-items:flex-end;gap:.85rem;flex-wrap:wrap;}}\
        .inline{{display:inline-flex;align-items:center;gap:.55rem;font-weight:500;}}\
        .inline input{{width:auto;}}\
        .badge{{display:inline-flex;align-items:center;padding:.23rem .68rem;border-radius:999px;font-size:.78rem;font-weight:700;letter-spacing:.03em;color:#fff;}}\
        .badge-ok{{background:var(--ok);}}\
        .badge-warn{{background:var(--warn);}}\
        .badge-high{{background:var(--high);}}\
        .badge-medium{{background:#c2410c;}}\
        .badge-low{{background:#475569;}}\
        table{{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;background:#fff;border:1px solid var(--line);border-radius:.9rem;}}\
        th,td{{padding:.8rem .95rem;text-align:left;vertical-align:top;border-bottom:1px solid #e6edf4;}}\
        thead th{{font-size:.74rem;letter-spacing:.08em;text-transform:uppercase;background:#f8fafc;font-weight:700;color:var(--muted);}}\
        tbody tr:hover td{{background:#fbfdff;}}\
        tbody tr:last-child td{{border-bottom:0;}}\
        .empty{{color:var(--muted);font-style:italic;}}\
        pre{{max-height:32rem;overflow:auto;background:#101828;color:#e2e8f0;padding:1rem;border:1px solid #1f2937;border-radius:.9rem;}}\
        .note{{color:var(--muted);background:#f8fafc;border:1px solid var(--line);padding:.85rem .95rem;border-radius:.8rem;}}\
        .source-link{{display:inline-flex;align-items:center;gap:.45rem;text-decoration:none;font-weight:700;}}\
        .source-link span{{text-decoration:underline;text-underline-offset:.18em;}}\
        .secret-grid{{display:grid;grid-template-columns:1fr;gap:.9rem;margin-bottom:1rem;}}\
        .secret-card{{display:grid;gap:.9rem;padding:1rem;border:1px solid var(--line);border-radius:1rem;background:#fff;}}\
        .secret-card__head{{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;}}\
        .secret-card__head h3{{margin:0;font-size:1.02rem;}}\
        .secret-card__meta{{margin:.18rem 0 0;color:var(--muted);font-size:.92rem;}}\
        .secret-card__value{{padding:.78rem .9rem;border:1px dashed var(--line);border-radius:.8rem;background:#f8fafc;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}}\
        .secret-card__actions{{display:flex;gap:.65rem;flex-wrap:wrap;align-items:center;}}\
        .secret-card__actions form{{display:inline;}}\
        .settings-flags{{display:flex;gap:.9rem;flex-wrap:wrap;}}\
        @media (min-width: 56rem){{.grid-2{{grid-template-columns:repeat(2,minmax(0,1fr));}}}}\
        @media (min-width: 64rem){{.secret-grid{{grid-template-columns:repeat(3,minmax(0,1fr));}}}}\
        @media (max-width: 55.999rem){{.topbar{{position:static;}} .nav{{width:100%;}} .nav a{{flex:1 1 auto;text-align:center;}} .section-head{{align-items:stretch;}} .section-actions,.toolbar{{width:100%;}} .section-actions form,.toolbar form{{width:100%;}} .secret-card__head,.secret-card__actions{{align-items:stretch;}}}}\
        </style>\
        </head><body><div class='wrap'><header class='topbar'><strong>Security MCP</strong><nav class='nav'><a href='/'>Investigate</a><a href='/tools'>Tools</a><a href='/sources'>Sources</a><a href='/cache'>Cache</a><a href='/audit'>Audit</a><a href='/settings'>Settings</a></nav></header><main>{}</main></div></body></html>",
        html_escape(title),
        favicon_data_uri(),
        body
    )
}

fn required_env_for_source(source: &str) -> &'static str {
    match source {
        "nvd" => "NVD_API_KEY",
        "shodan" => "SHODAN_API_KEY",
        "greynoise" => "GREYNOISE_API_KEY",
        "abuseipdb" => "ABUSEIPDB_API_KEY",
        "virustotal" => "VIRUSTOTAL_API_KEY",
        "urlscan" => "URLSCAN_API_KEY",
        "github" => "GITHUB_TOKEN",
        "circl_passive_dns" => "CIRCL_PD_USER + CIRCL_PD_PASSWORD",
        _ => "-",
    }
}

fn local_ui_identity() -> AuthIdentity {
    AuthIdentity {
        method: "local_ui".to_string(),
        subject: "localhost".to_string(),
        scopes: vec![
            "mcp:read".to_string(),
            "mcp:tools".to_string(),
            "mcp:raw".to_string(),
            "mcp:admin".to_string(),
        ],
    }
}

fn checkbox_to_bool(value: Option<String>) -> bool {
    value.is_some()
}

fn random_hex_token(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    rand::fill(&mut bytes[..]);
    hex::encode(bytes)
}

fn apply_env_updates(updates: &[(String, String)]) -> anyhow::Result<()> {
    let path = ".env";
    let existing = fs::read_to_string(path).unwrap_or_default();
    let mut lines = if existing.is_empty() {
        Vec::new()
    } else {
        existing
            .lines()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    };

    for (key, value) in updates {
        let mut updated = false;
        let entry = format!("{key}={}", format_env_value(value));
        for line in &mut lines {
            if line.starts_with(&format!("{key}=")) {
                *line = entry.clone();
                updated = true;
                break;
            }
        }
        if !updated {
            lines.push(entry);
        }
    }

    let output = format!("{}\n", lines.join("\n"));
    fs::write(path, output)?;
    Ok(())
}

fn format_env_value(value: &str) -> String {
    if value
        .chars()
        .any(|c| c.is_whitespace() || c == '#' || c == '"' || c == '\'')
    {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn favicon_svg_content() -> String {
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/favicon.svg")).to_string()
}

async fn favicon_svg() -> String {
    favicon_svg_content()
}

fn ui_script_content() -> String {
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/ui.js")).to_string()
}

async fn ui_script() -> String {
    ui_script_content()
}

fn favicon_data_uri() -> String {
    format!(
        "data:image/svg+xml,{}",
        urlencoding::encode(&favicon_svg_content())
    )
}

fn filter_icon() -> &'static str {
    "<svg aria-hidden='true' viewBox='0 0 20 20' width='14' height='14' fill='none'><path d='M3 4h14l-5.2 6.1V16l-3.6-1.9v-4L3 4z' fill='currentColor'/></svg>"
}

fn copy_icon() -> &'static str {
    "<svg aria-hidden='true' viewBox='0 0 20 20' width='14' height='14' fill='none'><path d='M7 3h8a2 2 0 0 1 2 2v8h-2V5H7V3Z' fill='currentColor'/><path d='M5 7h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V9a2 2 0 0 1 2-2Zm0 2v8h8V9H5Z' fill='currentColor'/></svg>"
}

fn refresh_icon() -> &'static str {
    "<svg aria-hidden='true' viewBox='0 0 20 20' width='14' height='14' fill='none'><path d='M4 10a6 6 0 0 1 10-4.5V3h2v5h-5V6h2.3A4 4 0 1 0 14 14l1.4 1.4A6 6 0 1 1 4 10Z' fill='currentColor'/></svg>"
}

fn external_icon() -> &'static str {
    "<svg aria-hidden='true' viewBox='0 0 20 20' width='13' height='13' fill='none'><path d='M11 3h6v6h-2V6.4l-6.8 6.8-1.4-1.4L13.6 5H11V3Z' fill='currentColor'/><path d='M4 5h5V3H3v6h2V5Zm0 10V10H2v7h7v-2H4Z' fill='currentColor'/></svg>"
}

fn token_kind_from_slug(slug: &str) -> Option<TokenKind> {
    match slug {
        "bearer" => Some(TokenKind::Bearer),
        "api-key" | "api_key" => Some(TokenKind::ApiKey),
        "connector" => Some(TokenKind::Connector),
        _ => None,
    }
}

fn token_kind_label(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Bearer => "Bearer token",
        TokenKind::ApiKey => "API key",
        TokenKind::Connector => "Connector token",
    }
}

fn token_kind_slug(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Bearer => "bearer",
        TokenKind::ApiKey => "api-key",
        TokenKind::Connector => "connector",
    }
}

fn token_kind_env_key(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Bearer => "SECURITY_MCP_BEARER_TOKEN",
        TokenKind::ApiKey => "SECURITY_MCP_API_KEY",
        TokenKind::Connector => "SECURITY_MCP_CONNECTOR_TOKEN",
    }
}

fn token_kind_current(kind: TokenKind, state: &AppState) -> Option<&str> {
    match kind {
        TokenKind::Bearer => state.config.bearer_token.as_deref(),
        TokenKind::ApiKey => state.config.api_key.as_deref(),
        TokenKind::Connector => state.config.connector_token.as_deref(),
    }
}

fn token_kind_placeholder(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Bearer => "Bearer token hidden",
        TokenKind::ApiKey => "API key hidden",
        TokenKind::Connector => "Connector token hidden",
    }
}

fn token_card(kind: TokenKind, current: Option<&str>) -> String {
    let configured = current.is_some();
    let status = if configured {
        "<span class='badge badge-ok'>configured</span>"
    } else {
        "<span class='badge badge-warn'>not set</span>"
    };
    let copy_disabled = if configured { "" } else { "disabled" };
    let label = token_kind_label(kind);
    let slug = token_kind_slug(kind);
    format!(
        "<article class='secret-card'>\
          <div class='secret-card__head'>\
            <div><h3>{}</h3><p class='secret-card__meta'>{}</p></div>\
            <div>{}</div>\
          </div>\
          <div class='secret-card__value'>{}</div>\
          <div class='secret-card__actions'>\
            <button type='button' class='button button-outline button-icon' data-label='Copy' data-copy-endpoint='/settings/token/{}/copy' {}>{} <span>Copy</span></button>\
            <form method='post' action='/settings/token/{}/regenerate'>\
              <button type='submit' class='button button-icon'>{} <span>Regenerate</span></button>\
            </form>\
          </div>\
        </article>",
        label,
        if configured {
            "Stored in .env and kept out of the page chrome."
        } else {
            "Not configured yet."
        },
        status,
        token_kind_placeholder(kind),
        copy_disabled,
        copy_icon(),
        slug,
        slug,
        refresh_icon()
    )
}

fn source_website_url(source: &str) -> Option<&'static str> {
    match source {
        "abuseipdb" => Some("https://www.abuseipdb.com/"),
        "circl_passive_dns" => Some("https://www.circl.lu/services/passive-dns/"),
        "cisa_kev" => Some("https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        "crtsh" => Some("https://crt.sh/"),
        "dns_over_https" => Some("https://developers.google.com/speed/public-dns/docs/doh"),
        "epss" => Some("https://www.first.org/epss/"),
        "github" => Some("https://github.com/"),
        "greynoise" => Some("https://www.greynoise.io/"),
        "http" => Some("https://developer.mozilla.org/en-US/docs/Web/HTTP"),
        "malwarebazaar" => Some("https://bazaar.abuse.ch/"),
        "nvd" => Some("https://nvd.nist.gov/"),
        "osv" => Some("https://osv.dev/"),
        "ransomwhere" => Some("https://ransomwhe.re/"),
        "rdap" => Some("https://datatracker.ietf.org/doc/html/rfc9083"),
        "shodan" => Some("https://www.shodan.io/"),
        "threatfox" => Some("https://threatfox.abuse.ch/"),
        "urlscan" => Some("https://urlscan.io/"),
        "virustotal" => Some("https://www.virustotal.com/"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config, db::Database, modules::Registry, oauth::SimpleRateLimiter, types::AppState,
    };
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;
    use url::Url;

    async fn test_state() -> AppState {
        let config = Config {
            bind_addr: "127.0.0.1:8080".parse().expect("bind addr"),
            public_base_url: Url::parse("http://127.0.0.1:8080").expect("base url"),
            oauth_issuer: Url::parse("http://127.0.0.1:8080").expect("issuer"),
            database_path: ":memory:".to_string(),
            public_mode: false,
            bearer_token: Some("bearer-secret".to_string()),
            bearer_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            api_key: Some("api-secret".to_string()),
            api_key_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            api_key_header: "X-API-Key".to_string(),
            api_key_query_enabled: false,
            api_key_query_name: "api_key".to_string(),
            connector_token: Some("connector-secret".to_string()),
            oauth_enabled: false,
            oauth_allowed_scopes: vec![
                "mcp:read".to_string(),
                "mcp:tools".to_string(),
                "mcp:raw".to_string(),
                "mcp:admin".to_string(),
            ],
            oauth_default_scopes: vec!["mcp:read".to_string(), "mcp:tools".to_string()],
            oauth_require_resource: false,
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
        };
        let db = Database::connect("sqlite::memory:").await.expect("db");
        db.migrate().await.expect("migrate");
        AppState {
            config,
            db,
            registry: Registry::new(false),
            http_client: reqwest::Client::new(),
            auth_rate_limiter: SimpleRateLimiter::new(100, std::time::Duration::from_secs(60)),
            lookup_rate_limiter: SimpleRateLimiter::new(100, std::time::Duration::from_secs(60)),
        }
    }

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
                    .header("host", "127.0.0.1:8080")
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

    #[test]
    fn render_page_does_not_depend_on_remote_assets() {
        let html = render_page("Test", "<p>body</p>");
        assert!(!html.contains("cdnjs.cloudflare.com"));
        assert!(!html.contains("fonts.googleapis.com"));
    }

    #[test]
    fn render_page_includes_favicon() {
        let html = render_page("Test", "<p>body</p>");
        assert!(html.contains("rel='icon'"));
        assert!(html.contains("data:image/svg+xml"));
    }

    #[tokio::test]
    async fn sources_page_links_to_websites() {
        let html = sources(State(Arc::new(test_state().await))).await.0;
        assert!(html.contains("https://nvd.nist.gov"));
        assert!(html.contains("https://www.shodan.io"));
    }

    #[tokio::test]
    async fn cache_page_uses_compact_header() {
        let html = cache(
            State(Arc::new(test_state().await)),
            Query(CacheQuery { limit: None }),
        )
        .await
        .0;
        assert!(html.contains("section-head"));
        assert!(html.contains("Clear Cache"));
    }

    #[tokio::test]
    async fn tools_page_uses_filter_icon_markup() {
        let html = tools(
            State(Arc::new(test_state().await)),
            Query(ToolsQuery {
                category: None,
                configured_only: None,
            }),
        )
        .await
        .0;
        assert!(html.contains("button-icon"));
        assert!(html.contains("Filter"));
    }

    #[tokio::test]
    async fn settings_page_hides_secret_values() {
        let state = test_state().await;
        let response = settings(
            State(Arc::new(state)),
            None,
            Query(SettingsQuery { message: None }),
        )
        .await;
        let html = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("settings body");
        let html = String::from_utf8(html.to_vec()).expect("settings html");

        assert!(!html.contains("bearer-secret"));
        assert!(!html.contains("api-secret"));
        assert!(!html.contains("connector-secret"));
        assert!(html.contains("data-copy-endpoint"));
        assert!(html.contains("regenerate"));
    }
}
