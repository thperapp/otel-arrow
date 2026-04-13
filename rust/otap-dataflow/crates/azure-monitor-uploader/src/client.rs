// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;

use rand::{RngExt, SeedableRng, rngs::SmallRng};
use reqwest::{
    Client,
    header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE, HeaderValue},
};
use tokio::time::{Duration, Instant};

use crate::config::ApiConfig;
use crate::error::Error;

const MAX_RETRIES: u32 = 5;
const INITIAL_BACKOFF: Duration = Duration::from_secs(3);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const MAX_IDLE_CONNECTIONS_PER_HOST: usize = 2;

/// HTTP header name for Azure Monitor source resource ID tracking.
pub const AZURE_MONITOR_SOURCE_RESOURCEID_HEADER: &str = "azure-monitor-source-resourceid";

/// URL-encode a value for use in an HTTP header (RFC 3986 percent-encoding).
pub fn url_encode_header_value(value: &str) -> String {
    urlencoding::encode(value).into_owned()
}

/// HTTP client for Azure Log Analytics Data Collection Rule (DCR) endpoint.
///
/// Handles authentication, compression, and HTTP communication with the
/// Azure Monitor Logs Ingestion API.
#[derive(Clone)]
pub struct LogsIngestionClient {
    http_client: Client,
    endpoint: String,

    // Pre-formatted authorization header provider
    auth_header: HeaderValue,

    /// Optional ARM resource ID header for Azure Monitor source tracking.
    resource_id_header: Option<HeaderValue>,
}

/// Pool of [`LogsIngestionClient`] instances for concurrent exports.
pub struct LogsIngestionClientPool {
    clients: Vec<LogsIngestionClient>,
}

impl LogsIngestionClientPool {
    /// Create a new pool with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            clients: Vec::with_capacity(capacity),
        }
    }

    fn create_http_clients(&self, count: usize) -> Result<Vec<Client>, Error> {
        let mut clients = Vec::with_capacity(count);

        for _ in 0..count {
            let http_client = Client::builder()
                .http1_only()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_HOST)
                .pool_idle_timeout(Duration::from_secs(90))
                .tcp_nodelay(true)
                .build()
                .map_err(Error::CreateClient)?;

            clients.push(http_client);
        }

        Ok(clients)
    }

    pub async fn initialize(&mut self, config: &ApiConfig) -> Result<(), Error> {
        let http_clients = self.create_http_clients(self.clients.capacity())?;

        for http_client in http_clients {
            let client = LogsIngestionClient::new(config, http_client)?;
            self.clients.push(client);
        }

        Ok(())
    }

    pub fn update_auth(&mut self, header: HeaderValue) {
        for client in &mut self.clients {
            client.update_auth(header.clone());
        }
    }

    #[inline(always)]
    pub fn take(&mut self) -> LogsIngestionClient {
        self.clients.pop().expect("client pool is empty")
    }

    #[inline(always)]
    pub fn release(&mut self, client: LogsIngestionClient) {
        self.clients.push(client);
    }
}

impl LogsIngestionClient {
    /// Creates a new Azure Monitor logs ingestion client instance from provided components.
    ///
    /// Primarily used for testing. The auth header is initialized with a placeholder
    /// and should be updated via `update_auth()` before making requests.
    ///
    /// # Arguments
    /// * `http_client` - The HTTP client to use for requests
    /// * `endpoint` - The full endpoint URL for the Azure Monitor ingestion API
    ///
    /// # Returns
    /// A configured client instance with a placeholder auth header
    #[must_use]
    pub fn from_parts(
        http_client: Client,
        endpoint: String,
    ) -> Self {
        Self {
            http_client,
            endpoint,
            auth_header: HeaderValue::from_static("Bearer "), // placeholder, will be updated on first use
            resource_id_header: None,
        }
    }

    /// Creates a new Azure Monitor logs ingestion client instance from the configuration.
    ///
    /// The auth header is initialized with a placeholder and should be updated
    /// via `update_auth()` before making requests.
    ///
    /// # Arguments
    /// * `config` - The API configuration containing endpoint, DCR, and stream info
    /// * `http_client` - The HTTP client to use for requests
    ///
    /// # Returns
    /// * `Ok(LogsIngestionClient)` - A configured client instance
    /// * `Err(Error)` - If client initialization fails
    pub fn new(
        config: &ApiConfig,
        http_client: Client,
    ) -> Result<Self, Error> {
        let endpoint = format!(
            "{}/dataCollectionRules/{}/streams/{}?api-version=2021-11-01-preview",
            config.dcr_endpoint, config.dcr, config.stream_name
        );

        let resource_id_header = config
            .azure_monitor_source_resourceid
            .as_deref()
            .and_then(|v| {
                let encoded = url_encode_header_value(v);
                HeaderValue::from_str(&encoded).ok()
            });

        Ok(Self {
            http_client,
            endpoint,
            auth_header: HeaderValue::from_static("Bearer "), // placeholder, will be updated on first use
            resource_id_header,
        })
    }

    /// Update the authorization header with a new access token.
    pub fn update_auth(&mut self, header: HeaderValue) {
        self.auth_header = header;
    }

    /// Export compressed data to Log Analytics ingestion API with automatic retry.
    ///
    /// Retries on:
    /// - Network errors
    /// - 401 (after token refresh)
    /// - 429 (rate limiting) - uses Retry-After header if present
    /// - 5xx (server errors)
    ///
    /// # Arguments
    /// * `body` - The gzip-compressed JSON data to send
    ///
    /// # Returns
    /// * `Ok(Duration)` - Total time spent (including retries) if successful
    /// * `Err(String)` - Error message if all retries exhausted or non-retryable error
    pub async fn export(&mut self, body: Bytes) -> Result<Duration, Error> {
        let mut attempt = 0u32;
        let mut rng = SmallRng::seed_from_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time before UNIX epoch")
                .as_nanos() as u64
                ^ (self as *const _ as u64),
        );

        loop {
            match self.try_export(body.clone()).await {
                Ok(duration) => return Ok(duration),
                Err(e) if !e.is_retryable() => {
                    return Err(Error::ExportFailed {
                        attempts: attempt + 1,
                        last_error: Box::new(e),
                    });
                }
                Err(e) => {
                    attempt += 1;

                    // ToDo: Add an upper bound for server-driven retries (429/5xx with
                    // Retry-After). Currently only the non-server-driven path enforces
                    // MAX_RETRIES; a server that perpetually returns 429 with Retry-After
                    // will cause this loop to retry indefinitely.
                    let delay = if let Some(server_delay) = e.retry_after() {
                        let base_delay = server_delay.max(Duration::from_secs(5));
                        let jitter = Duration::from_secs(3)
                            + Duration::from_secs_f64(rng.random::<f64>() * 7.0);
                        base_delay + jitter
                    } else {
                        if attempt >= MAX_RETRIES {
                            return Err(Error::ExportFailed {
                                attempts: attempt,
                                last_error: Box::new(e),
                            });
                        }
                        let backoff = INITIAL_BACKOFF * 2u32.pow(attempt - 1);
                        let base_delay = backoff.min(MAX_BACKOFF);
                        let jitter_factor = 0.85 + rng.random::<f64>() * 0.30;
                        base_delay.mul_f64(jitter_factor)
                    };

                    // TODO: Revisit whether DEBUG or INFO is the right level for retry attempts.

                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Single export attempt without retry logic.
    async fn try_export(&mut self, body: Bytes) -> Result<Duration, Error> {
        let start = Instant::now();

        let mut request = self
            .http_client
            .post(&self.endpoint)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_ENCODING, "gzip")
            .header(AUTHORIZATION, &self.auth_header);

        if let Some(ref resource_id) = self.resource_id_header {
            request = request.header(AZURE_MONITOR_SOURCE_RESOURCEID_HEADER, resource_id);
        }

        let response = match request.body(body).send().await {
            Ok(resp) => resp,
            Err(e) => {
                return Err(Error::network(e));
            }
        };

        let elapsed = start.elapsed();

        if response.status().is_success() {
            return Ok(elapsed);
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

