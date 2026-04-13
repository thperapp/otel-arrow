// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Exporter-specific error types that wrap the library error with engine context.

/// Error definitions for the Azure Monitor exporter.
///
/// Wraps [`azure_monitor_uploader::error::Error`] for library errors and adds
/// exporter-specific variants for engine integration (logs view creation,
/// channel receive, auth handler setup, client pool initialization).
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// An error originating from the azure-monitor-uploader library.
    #[error(transparent)]
    Uploader(#[from] azure_monitor_uploader::error::Error),

    /// Failed to create logs view from OTAP Arrow records.
    #[error("Failed to create logs view")]
    LogsViewCreationFailed {
        /// The underlying pdata error.
        #[source]
        source: otap_df_pdata::error::Error,
    },

    /// Channel receive error.
    #[error("Channel receive error")]
    ChannelRecv(#[source] otap_df_channel::error::RecvError),

    /// Failed to create auth handler.
    #[error("Failed to create auth handler")]
    AuthHandlerCreation(#[source] Box<azure_monitor_uploader::error::Error>),

    /// Client pool initialization failed.
    #[error("Client pool initialization failed")]
    ClientPoolInit(#[source] Box<azure_monitor_uploader::error::Error>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn test_uploader_error_transparent() {
        let uploader_err = azure_monitor_uploader::error::Error::LogEntryTooLarge;
        let error = Error::Uploader(uploader_err);
        assert_eq!(error.to_string(), "Log entry too large to export");
    }

    #[test]
    fn test_from_uploader_error() {
        let uploader_err = azure_monitor_uploader::error::Error::PayloadTooLarge;
        let error: Error = uploader_err.into();
        assert_eq!(error.to_string(), "Payload too large");
    }

    #[test]
    fn test_logs_view_creation_failed_message() {
        let error = Error::LogsViewCreationFailed {
            source: otap_df_pdata::error::Error::ColumnNotFound {
                name: "test_column".to_string(),
            },
        };
        assert_eq!(error.to_string(), "Failed to create logs view");
        assert!(error.source().is_some());
    }

    #[test]
    fn test_channel_recv_message() {
        let recv_error = otap_df_channel::error::RecvError::Closed;
        let error = Error::ChannelRecv(recv_error);
        assert_eq!(error.to_string(), "Channel receive error");
        assert!(error.source().is_some());
    }

    #[test]
    fn test_auth_handler_creation_message() {
        let inner = azure_monitor_uploader::error::Error::Config("test".to_string());
        let error = Error::AuthHandlerCreation(Box::new(inner));
        assert_eq!(error.to_string(), "Failed to create auth handler");
        assert!(error.source().is_some());
    }

    #[test]
    fn test_client_pool_init_message() {
        let inner = azure_monitor_uploader::error::Error::Config("test".to_string());
        let error = Error::ClientPoolInit(Box::new(inner));
        assert_eq!(error.to_string(), "Client pool initialization failed");
        assert!(error.source().is_some());
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Error>();
    }

    #[test]
    fn test_error_implements_std_error() {
        fn assert_std_error<T: StdError>() {}
        assert_std_error::<Error>();
    }
}
