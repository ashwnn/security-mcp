use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use dotenvy::dotenv;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

mod auth;
mod cache;
mod config;
mod db;
mod mcp;
mod modules;
mod oauth;
mod rate_limit;
mod types;
mod ui;
mod validation;

use auth::AuthLayer;
use config::Cli;
use db::Database;
use modules::Registry;
use rate_limit::{QuotaTracker, RateLimitPolicy};
use types::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    let cli = Cli::parse();
    let config = config::Config::from_sources(cli)?;

    tracing_subscriber::fmt()
        .with_env_filter(config.log_level.clone())
        .with_target(false)
        .compact()
        .init();

    let db = Database::connect(&config.database_path).await?;
    db.migrate().await?;

    let registry = Registry::new(config.expert_tool_enabled);
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            config.default_timeout_seconds,
        ))
        .user_agent("security-mcp/0.1.0")
        .build()
        .context("failed to build reqwest client")?;

    let policy = RateLimitPolicy {
        default_plan: match config.rate_limit_default_plan.as_str() {
            "paid" => rate_limit::RateLimitPlan::Paid,
            "enterprise" => rate_limit::RateLimitPlan::Enterprise,
            "unlimited" => rate_limit::RateLimitPlan::Unlimited,
            _ => rate_limit::RateLimitPlan::Free,
        },
        warn_remaining_percent: config.rate_limit_warn_remaining_percent,
        block_remaining_percent: config.rate_limit_block_remaining_percent,
        soft_block_enabled: config.rate_limit_soft_block_enabled,
    };

    let quota_tracker = Arc::new(QuotaTracker::new(policy));

    let state = Arc::new(AppState {
        config: config.clone(),
        db,
        registry,
        http_client,
        auth_rate_limiter: oauth::SimpleRateLimiter::new(
            config.auth_rate_limit_per_minute,
            std::time::Duration::from_secs(60),
        ),
        lookup_rate_limiter: oauth::SimpleRateLimiter::new(
            config.lookup_rate_limit_per_minute,
            std::time::Duration::from_secs(60),
        ),
        quota_tracker,
    });

    let auth_layer = AuthLayer::new(state.clone());
    let security_headers = ServiceBuilder::new()
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::X_CONTENT_TYPE_OPTIONS,
            http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::REFERRER_POLICY,
            http::HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::X_FRAME_OPTIONS,
            http::HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::CONTENT_SECURITY_POLICY,
            http::HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            http::header::STRICT_TRANSPORT_SECURITY,
            http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));

    let app = ui::router(state.clone(), auth_layer.clone())
        .merge(mcp::router(state, auth_layer))
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(config.max_request_body_bytes))
        .layer(
            TraceLayer::new_for_http()
                .on_request(|request: &http::Request<_>, _span: &tracing::Span| {
                    tracing::info!(
                        method = %request.method(),
                        uri = %redacted_path_and_query(request.uri()),
                        "request started"
                    );
                })
                .on_response(
                    |response: &http::Response<_>,
                     latency: std::time::Duration,
                     _span: &tracing::Span| {
                        tracing::info!(
                            status = %response.status(),
                            latency_ms = latency.as_millis(),
                            "request completed"
                        );
                    },
                ),
        )
        .layer(security_headers);

    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.bind_addr))?;

    let local_addr: SocketAddr = listener
        .local_addr()
        .context("failed to read local listener address")?;

    if config.public_mode && !local_addr.ip().is_loopback() {
        info!(bind = %local_addr, "running in explicit public mode");
    } else if !local_addr.ip().is_loopback() {
        warn!(bind = %local_addr, "non-loopback bind without public mode, verify deployment intent");
    }

    info!(bind = %local_addr, public_mode = config.public_mode, "security-mcp started");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("server failed")?;
    Ok(())
}

fn redacted_path_and_query(uri: &http::Uri) -> String {
    let path = uri.path();
    let Some(query) = uri.query() else {
        return path.to_string();
    };
    let redacted = url::form_urlencoded::parse(query.as_bytes())
        .map(|(k, v)| {
            let key = k.to_string();
            let sensitive = matches!(
                key.as_str(),
                "api_key" | "token" | "access_token" | "code" | "connector_token"
            );
            if sensitive {
                format!("{key}=<redacted>")
            } else {
                format!("{}={}", key, v)
            }
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{path}?{redacted}")
}
