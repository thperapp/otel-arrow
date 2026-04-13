// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::client::AZURE_MONITOR_SOURCE_RESOURCEID_HEADER;
use crate::config::{ApiConfig, HeartbeatOverrides};
use crate::error::Error;
use chrono::Utc;
use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue},
};
use std::time::Duration;
use sysinfo::System;

const HEARTBEAT_STREAM_NAME: &str = "HEALTH_ASSESSMENT_BLOB";
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 2;

/// Heartbeat client for Azure Monitor Exporter.
pub struct Heartbeat {
    client: Client,
    endpoint: String,
    heartbeat_row: HeartbeatRow,

    /// Pre-formatted authorization header for zero-allocation reuse
    pub auth_header: HeaderValue,

    /// Optional ARM resource ID header for Azure Monitor source tracking.
    resource_id_header: Option<HeaderValue>,
}

#[derive(Serialize)]
struct HeartbeatRow {
    #[serde(rename = "Time")]
    time: String,

    #[serde(rename = "Computer")]
    computer: String,

    #[serde(rename = "OSType")]
    os_type: String,

    #[serde(rename = "OSName")]
    os_name: String,

    #[serde(rename = "OSMajorVersion")]
    os_major_version: String,

    #[serde(rename = "OSMinorVersion")]
    os_minor_version: String,

    #[serde(rename = "Version")]
    version: String,
}

#[inline]
fn default_heartbeat_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[inline]
fn default_heartbeat_os_name() -> String {
    System::name().unwrap_or_else(|| std::env::consts::OS.to_string())
}

#[inline]
fn default_heartbeat_computer() -> String {
    std::env::var("HOSTNAME")
        .unwrap_or_else(|_| System::host_name().unwrap_or_else(|| "UnknownComputer".to_string()))
}

/// Parse OS version into (major, minor) components
/// e.g., "22.04.3" -> ("22", "04")
/// e.g., "10 (22H2)" -> ("10", "22H2")
/// e.g., "5.15.0-generic" -> ("5", "15")
fn parse_os_version() -> (String, String) {
    let version = System::os_version().unwrap_or_default();

    if version.is_empty() {
        return ("Unknown".to_string(), "Unknown".to_string());
    }

    // Handle Windows format: "10 (22H2)"
    if let Some(paren_start) = version.find('(') {
        let major = version[..paren_start].trim().to_string();
        let minor = version[paren_start..]
            .trim_matches(|c| c == '(' || c == ')')
            .to_string();
        return (major, minor);
    }

    // Handle semver format: "22.04.3" or "5.15.0-generic"
    let parts: Vec<&str> = version.split('.').collect();
    match parts.as_slice() {
        [major] => (major.to_string(), "0".to_string()),
        [major, minor, ..] => (major.to_string(), minor.to_string()),
        [] => ("Unknown".to_string(), "Unknown".to_string()),
    }
}

#[inline]
fn default_heartbeat_os_type() -> String {
    match std::env::consts::OS {
        "linux" => "Linux".to_string(),
        "windows" => "Windows".to_string(),
        "macos" => "MacOS".to_string(),
        other => other.to_string(),
    }
}

impl Heartbeat {
    /// Create a new Heartbeat instance.
    pub fn new(config: &ApiConfig, overrides: &HeartbeatOverrides) -> Result<Self, Error> {
        let http_client = Client::builder()
            .http1_only()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_nodelay(true)
            .build()
            .map_err(Error::CreateClient)?;

        let (os_major, os_minor) = parse_os_version();

        Ok(Self {
            client: http_client,
            endpoint: format!(
                "{}/dataCollectionRules/{}/streams/{}?api-version=2021-11-01-preview",
                config.dcr_endpoint, config.dcr, HEARTBEAT_STREAM_NAME
            ),
            heartbeat_row: HeartbeatRow {
                time: Utc::now().to_rfc3339(),
                computer: overrides
                    .computer
                    .clone()
                    .unwrap_or_else(default_heartbeat_computer),
                os_type: overrides
                    .os_type
                    .clone()
                    .unwrap_or_else(default_heartbeat_os_type),
                os_name: overrides
                    .os_name
                    .clone()
                    .unwrap_or_else(default_heartbeat_os_name),
                os_major_version: overrides.os_major_version.clone().unwrap_or(os_major),
                os_minor_version: overrides.os_minor_version.clone().unwrap_or(os_minor),
                version: overrides
                    .version
                    .clone()
                    .unwrap_or_else(default_heartbeat_version),
            },
            auth_header: HeaderValue::from_static("Bearer "),
            resource_id_header: config
                .azure_monitor_source_resourceid
                .as_deref()
                .and_then(|v| {
                    let encoded = super::client::url_encode_header_value(v);
                    HeaderValue::from_str(&encoded).ok()
                }),
        })
    }

    /// Create a Heartbeat from individual components (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn from_parts(client: Client, endpoint: String) -> Self {
        Self {
            client,
            endpoint,
            heartbeat_row: HeartbeatRow {
                time: Utc::now().to_rfc3339(),
                computer: "test-computer".to_string(),
                os_type: "Linux".to_string(),
                os_name: "test-os".to_string(),
                os_major_version: "1".to_string(),
                os_minor_version: "0".to_string(),
                version: "test-version".to_string(),
            },
            auth_header: HeaderValue::from_static("Bearer "),
            resource_id_header: None,
        }
    }

    /// Update the authorization header with a new access token.
    pub fn update_auth(&mut self, header: HeaderValue) {
        self.auth_header = header;
    }

    /// Send a heartbeat to the Azure Monitor Logs Ingestion endpoint.
    pub async fn send(&mut self) -> Result<(), Error> {
        self.heartbeat_row.time = Utc::now().to_rfc3339();
        let payload = serde_json::json!([self.heartbeat_row]);
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, &self.auth_header);

        if let Some(ref resource_id) = self.resource_id_header {
            request = request.header(AZURE_MONITOR_SOURCE_RESOURCEID_HEADER, resource_id);
        }

        let response = request
            .body(payload.to_string())
            .send()
            .await
            .map_err(Error::network)?;

        if response.status().is_success() {
            return Ok(());
        }

        // Extract Retry-After header before consuming response
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs);

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        match status.as_u16() {
            401 => Err(Error::unauthorized(body)),
            403 => Err(Error::forbidden(body)),
            413 => Err(Error::PayloadTooLarge),
            429 => Err(Error::RateLimited { body, retry_after }),
            500..=599 => Err(Error::ServerError {
                status,
                body,
                retry_after,
            }),
            _ => Err(Error::UnexpectedStatus { status, body }),
        }
    }
}

