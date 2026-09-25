use crate::{ClientSecretError, ClientSecretVerifier, OidcClient, OidcClientType, StoreError};

pub(crate) fn authenticate_client(
    client: &OidcClient,
    provided_secret: Option<&str>,
    verifier: &impl ClientSecretVerifier,
) -> Result<(), StoreError> {
    if client.client_type != OidcClientType::ConfidentialWeb {
        return Ok(());
    }

    let provided_secret = provided_secret
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(StoreError::Conflict("oidc_client.client_secret"))?;
    let stored_secret_hash = client
        .client_secret_hash
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(StoreError::Conflict("oidc_client.client_secret"))?;

    let valid = verifier
        .verify_client_secret(provided_secret, stored_secret_hash)
        .map_err(store_error_from_client_secret)?;
    if valid {
        Ok(())
    } else {
        Err(StoreError::Conflict("oidc_client.authentication"))
    }
}

fn store_error_from_client_secret(error: ClientSecretError) -> StoreError {
    StoreError::Backend(format!("client_secret:{error:?}"))
}

#[cfg(test)]
mod tests {
    use crate::{ClientSecretError, ClientSecretVerifier, OidcClient, OidcClientType};

    use super::authenticate_client;

    struct TestVerifier {
        result: Result<bool, ClientSecretError>,
    }

    impl ClientSecretVerifier for TestVerifier {
        fn verify_client_secret(
            &self,
            _provided_secret: &str,
            _stored_secret_hash: &str,
        ) -> Result<bool, ClientSecretError> {
            self.result.clone()
        }
    }

    #[test]
    fn public_clients_skip_secret_authentication() {
        let client = OidcClient {
            client_id: "desktop-app".to_string(),
            client_name: "Desktop App".to_string(),
            redirect_uris: vec!["http://127.0.0.1:49152/callback".to_string()],
            client_type: OidcClientType::PublicDesktop,
            pkce_required: true,
            client_secret_hash: None,
        };

        assert_eq!(
            authenticate_client(&client, None, &TestVerifier { result: Ok(false) }),
            Ok(())
        );
    }

    #[test]
    fn confidential_clients_require_secret_and_verification() {
        let client = OidcClient {
            client_id: "web-app".to_string(),
            client_name: "Web App".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            client_type: OidcClientType::ConfidentialWeb,
            pkce_required: false,
            client_secret_hash: Some("secret-hash".to_string()),
        };

        assert_eq!(
            authenticate_client(&client, None, &TestVerifier { result: Ok(true) }),
            Err(crate::StoreError::Conflict("oidc_client.client_secret"))
        );
        assert_eq!(
            authenticate_client(
                &client,
                Some("wrong-secret"),
                &TestVerifier { result: Ok(false) }
            ),
            Err(crate::StoreError::Conflict("oidc_client.authentication"))
        );
        assert_eq!(
            authenticate_client(
                &client,
                Some("correct-secret"),
                &TestVerifier { result: Ok(true) }
            ),
            Ok(())
        );
    }
}
