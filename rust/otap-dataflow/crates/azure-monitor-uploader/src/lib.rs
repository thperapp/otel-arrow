// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Azure Monitor Uploader — core library for uploading telemetry data to Azure Monitor.
//!
//! This crate provides the core functionality for transforming, compressing, and
//! uploading OpenTelemetry logs to Azure Monitor using the Data Collection Rules (DCR) API.
//! It is designed to be consumed by thin exporter adapters (e.g., the `azure_monitor_exporter`
//! module in `otap-df-contrib-nodes`) following the same pattern as `geneva-uploader`.
//!
//! ## Data interface
//!
//! The transformer accepts any type implementing the [`LogsDataView`] trait from
//! `otap-df-pdata-views` — a zero-dependency trait crate. This preserves zero-copy
//! performance: callers can pass Arrow-backed views or raw OTLP byte views directly,
//! without intermediate protobuf deserialization.
//!
//! [`LogsDataView`]: otap_df_pdata_views::views::logs::LogsDataView
//!
//! ## Key types
//!
//! - [`Transformer`] — converts any [`LogsDataView`] impl into JSON `Bytes` entries.
//! - [`GzipBatcher`](gzip_batcher::GzipBatcher) — accumulates entries into gzip-compressed ≤1 MB batches.
//! - [`LogsIngestionClient`](client::LogsIngestionClient) / [`LogsIngestionClientPool`](client::LogsIngestionClientPool) — HTTP upload with retry.
//! - [`Auth`](auth::Auth) — Azure credential management and token acquisition.
//! - [`Config`] — YAML-deserializable configuration.
//! - [`Error`] — unified error enum with retryability classification.

/// Azure credential management and token acquisition.
pub mod auth;
/// HTTP client and client pool for the DCR ingestion API.
pub mod client;
/// YAML-deserializable configuration types.
pub mod config;
/// Unified error type with retryability classification.
pub mod error;
/// Gzip-compressed batching of JSON log entries.
pub mod gzip_batcher;
/// OTLP-to-Azure Log Analytics JSON transformer.
pub mod transformer;

pub use config::Config;
pub use error::Error;
pub use transformer::Transformer;
