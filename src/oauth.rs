use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenResponse};
use oauth2::prelude::*;
use oauth2::{AuthUrl, ClientId, ClientSecret, RefreshToken, RequestTokenError, Scope, TokenUrl};
use url::Url;

use anyhow::anyhow;

// NOTE: GCRCREDs "borrowed" from https://github.com/GoogleCloudPlatform/docker-credential-gcr/
// as they are the only ones that work with any localhost URL

/// GCRCRED_HELPER_CLIENT_ID is the client_id to be used when performing the
/// OAuth2 Authorization Code grant flow.
/// See https://developers.google.com/identity/protocols/OAuth2InstalledApp
const GCRCRED_HELPER_CLIENT_ID: &str =
    "99426463878-o7n0bshgue20tdpm25q4at0vs2mr4utq.apps.googleusercontent.com";

/// GCRCRED_HELPER_CLIENT_NOT_SO_SECRET is the client_secret to be used when
/// performing the OAuth2 Authorization Code grant flow.
/// See https://developers.google.com/identity/protocols/OAuth2InstalledApp
const GCRCRED_HELPER_CLIENT_NOT_SO_SECRET: &str = "HpVi8cnKx8AAkddzaNrSWmS8";

pub const GCRCRED_HELPER_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

pub fn map_oauth_err(e: RequestTokenError<BasicErrorResponseType>) -> anyhow::Error {
    match e {
        RequestTokenError::ServerResponse(e) => match e.error() {
            BasicErrorResponseType::InvalidRequest => anyhow!("Invalid request"),
            BasicErrorResponseType::InvalidClient => anyhow!("Invalid client"),
            BasicErrorResponseType::InvalidGrant => anyhow!("Invalid grant"),
            BasicErrorResponseType::UnauthorizedClient => anyhow!("Unauthorized client"),
            BasicErrorResponseType::UnsupportedGrantType => anyhow!("Unsupported grant type"),
            BasicErrorResponseType::InvalidScope => anyhow!("Invalid scope"),
        },
        RequestTokenError::Request(e) => e.into(),
        RequestTokenError::Parse(e, _) => e.into(),
        RequestTokenError::Other(msg) => anyhow!(msg),
    }
}

pub fn new_basic_client(client_id: Option<&str>, client_secret: Option<&str>) -> BasicClient {
    BasicClient::new(
        ClientId::new(client_id.unwrap_or(GCRCRED_HELPER_CLIENT_ID).to_string()),
        Some(ClientSecret::new(
            client_secret
                .unwrap_or(GCRCRED_HELPER_CLIENT_NOT_SO_SECRET)
                .to_string(),
        )),
        AuthUrl::new(Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap()),
        Some(TokenUrl::new(
            Url::parse("https://www.googleapis.com/oauth2/v3/token").unwrap(),
        )),
    )
}

pub fn new_client(
    client_id: Option<&str>,
    client_secret: Option<&str>,
    scope: &str,
) -> BasicClient {
    new_basic_client(client_id, client_secret).add_scope(Scope::new(scope.to_string()))
}

pub fn refresh(
    client_id: Option<&str>,
    client_secret: Option<&str>,
    scope: &str,
    refresh_token: &RefreshToken,
) -> anyhow::Result<BasicTokenResponse> {
    crate::oauth::new_client(client_id, client_secret, scope)
        .exchange_refresh_token(&refresh_token)
        .map_err(crate::oauth::map_oauth_err)
}
