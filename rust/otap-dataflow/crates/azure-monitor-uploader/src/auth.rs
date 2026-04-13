// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use azure_core::credentials::{AccessToken, TokenCredential};
use azure_identity::{
    DeveloperToolsCredential, DeveloperToolsCredentialOptions, ManagedIdentityCredential,
    ManagedIdentityCredentialOptions, UserAssignedId,
};
use futures::future::LocalBoxFuture;
use std::sync::Arc;

use crate::Error;
use crate::config::{AuthConfig, AuthMethod};

/// Result of a completed token acquisition, returning the `Auth` for reuse.
pub struct TokenRefreshResult {
    pub auth: Auth,
    pub result: Result<AccessToken, Error>,
}

/// Holds an optional in-flight token acquisition future.
/// Mirrors the `InFlightExports` pattern: `next_completion()` stays pending
/// when no future is in flight, and returns the result when one completes.
pub struct PendingTokenRefresh {
    future: Option<LocalBoxFuture<'static, TokenRefreshResult>>,
}

impl PendingTokenRefresh {
    pub fn new() -> Self {
        Self { future: None }
    }

    /// Returns `true` if a token acquisition is currently in progress.
    pub fn is_pending(&self) -> bool {
        self.future.is_some()
    }

    /// Start a new token acquisition. Panics if one is already in progress.
    pub fn start(&mut self, auth: Auth) {
        assert!(
            self.future.is_none(),
            "cannot start token refresh while one is already pending"
        );
        self.future = Some(auth.make_token_future());
    }

    /// Await the next token acquisition result.
    /// Stays pending forever if no acquisition is in flight.
    pub async fn next_completion(&mut self) -> TokenRefreshResult {
        match self.future.as_mut() {
            Some(fut) => {
                let result = fut.await;
                self.future = None;
                result
            }
            None => std::future::pending().await,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Auth {
    credential: Arc<dyn TokenCredential>,
    scope: String,
}

impl Auth {
    pub fn new(
        auth_config: &AuthConfig,
    ) -> Result<Self, Error> {
        let credential = Self::create_credential(auth_config)?;

        Ok(Self {
            credential,
            scope: auth_config.scope.clone(),
        })
    }

    #[cfg(test)]
    pub fn from_credential(
        credential: Arc<dyn TokenCredential>,
        scope: String,
    ) -> Self {
        Self {
            credential,
            scope,
        }
    }

    /// Attempt a single token acquisition (non-blocking, no retries).
    pub async fn get_token(&self) -> Result<AccessToken, Error> {
        let token_response = self
            .credential
            .get_token(
                &[&self.scope],
                Some(azure_core::credentials::TokenRequestOptions::default()),
            )
            .await
            .map_err(Error::token_acquisition)?;

        Ok(token_response)
    }

    /// Create a boxed future for token acquisition.
    /// Takes ownership of `Auth` and returns it alongside the result,
    /// so the caller can reclaim it after the future completes.
    fn make_token_future(self) -> LocalBoxFuture<'static, TokenRefreshResult> {
        Box::pin(async move {
            let result = self.get_token().await;
            TokenRefreshResult { auth: self, result }
        })
    }

    fn create_credential(auth_config: &AuthConfig) -> Result<Arc<dyn TokenCredential>, Error> {
        match auth_config.method {
            AuthMethod::ManagedIdentity => {
                let mut options = ManagedIdentityCredentialOptions::default();

                if let Some(client_id) = &auth_config.client_id {
                    options.user_assigned_id = Some(UserAssignedId::ClientId(client_id.clone()));
                }

                Ok(ManagedIdentityCredential::new(Some(options))
                    .map_err(|e| Error::create_credential(AuthMethod::ManagedIdentity, e))?)
            }
            AuthMethod::Development => Ok(DeveloperToolsCredential::new(Some(
                DeveloperToolsCredentialOptions::default(),
            ))
            .map_err(|e| Error::create_credential(AuthMethod::Development, e))?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::credentials::TokenRequestOptions;
    use azure_core::time::OffsetDateTime;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct MockCredential {
        token: String,
        expires_in: azure_core::time::Duration,
        call_count: Arc<AtomicUsize>,
    }

    fn make_mock_credential(
        token: &str,
        expires_in: azure_core::time::Duration,
        call_count: Arc<AtomicUsize>,
    ) -> Arc<dyn TokenCredential> {
        let cred: Arc<dyn TokenCredential> = Arc::new(MockCredential {
            token: token.to_string(),
            expires_in,
            call_count,
        });
        cred
    }

    #[async_trait::async_trait]
    impl TokenCredential for MockCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            let _ = self.call_count.fetch_add(1, Ordering::SeqCst);

            Ok(AccessToken {
                token: self.token.clone().into(),
                expires_on: OffsetDateTime::now_utc() + self.expires_in,
            })
        }
    }

    // ==================== Construction Tests ====================

    #[tokio::test]
    async fn test_from_credential_creates_auth() {
        let credential = make_mock_credential(
            "test_token",
            azure_core::time::Duration::minutes(60),
            Arc::new(AtomicUsize::new(0)),
        );

        let auth =
            Auth::from_credential(credential, "test_scope".to_string());
        assert_eq!(auth.scope, "test_scope");
    }

    // Note: test_new_with_managed_identity_* and test_new_with_development_auth
    // tests require a TLS crypto provider and are in the exporter's test suite.

    // ==================== Token Fetching Tests ====================

    #[tokio::test]
    async fn test_get_token_returns_valid_token() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let credential = make_mock_credential(
            "test_token",
            azure_core::time::Duration::minutes(60),
            call_count.clone(),
        );

        let auth = Auth::from_credential(credential, "scope".to_string());

        let token = auth.get_token().await.unwrap();
        assert_eq!(token.token.secret(), "test_token");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_get_token_calls_credential_each_time() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let credential = make_mock_credential(
            "test_token",
            azure_core::time::Duration::minutes(60),
            call_count.clone(),
        );

        let auth = Auth::from_credential(credential, "scope".to_string());

        // Each call to get_token should call the credential
        let _ = auth.get_token().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        let _ = auth.get_token().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 2);

        let _ = auth.get_token().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_get_token_returns_cloned_tokens() {
        let credential = make_mock_credential(
            "test_token",
            azure_core::time::Duration::minutes(60),
            Arc::new(AtomicUsize::new(0)),
        );

        let auth = Auth::from_credential(credential, "scope".to_string());

        let token1 = auth.get_token().await.unwrap();
        let token2 = auth.get_token().await.unwrap();

        // Same value from both calls
        assert_eq!(token1.token.secret(), token2.token.secret());
    }

    // ==================== Error Handling Tests ====================

    #[tokio::test]
    async fn test_get_token_propagates_credential_error() {
        #[derive(Debug)]
        struct FailingCredential;

        #[async_trait::async_trait]
        impl TokenCredential for FailingCredential {
            async fn get_token(
                &self,
                _scopes: &[&str],
                _options: Option<TokenRequestOptions<'_>>,
            ) -> azure_core::Result<AccessToken> {
                Err(azure_core::error::Error::new(
                    azure_core::error::ErrorKind::Credential,
                    "Mock credential failure",
                ))
            }
        }

        let cred = FailingCredential;
        let credential: Arc<dyn TokenCredential> = Arc::new(cred);
        let auth = Auth::from_credential(credential, "scope".to_string());

        let result = auth.get_token().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Auth {
                kind: crate::error::AuthErrorKind::TokenAcquisition,
                ..
            } => {}
            err => panic!("Expected Auth token acquisition error, got: {:?}", err),
        }
    }

    // ==================== Clone Behavior Tests ====================

    #[tokio::test]
    async fn test_cloned_auth_shares_credential() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let credential = make_mock_credential(
            "test_token",
            azure_core::time::Duration::minutes(60),
            call_count.clone(),
        );

        let auth1 = Auth::from_credential(credential, "scope".to_string());
        let auth2 = auth1.clone();

        // Both auth instances share the same credential
        let _ = auth1.get_token().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        let _ = auth2.get_token().await.unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 2);
    }

}
