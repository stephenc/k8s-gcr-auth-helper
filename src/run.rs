use clap::{App, Arg, ArgMatches, SubCommand};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event, Secret};
use kube::api::{ListParams, WatchEvent};
use kube::client::APIClient;
use kube::runtime::Informer;
use kube::{Api, Resource};
use oauth2::prelude::*;
use oauth2::{RefreshToken, TokenResponse};

use anyhow::anyhow;

use crate::common::KubeCrud;
use crate::{CredentialConfiguration, Credentials, Targets, Watcher};

pub struct Runner<'a> {
    client: APIClient,
    targets: Targets,
    secret_name: &'a str,
    scope: &'a str,
    client_id: Option<&'a str>,
    client_secret: Option<&'a str>,
    username: Option<&'a str>,
}

impl<'a> From<&'a Runner<'a>> for CredentialConfiguration<'a> {
    fn from(w: &'a Runner<'a>) -> Self {
        CredentialConfiguration::new(w.secret_name, &w.targets)
    }
}

impl Runner<'_> {
    pub fn subcommand(name: &str) -> App {
        SubCommand::with_name(name)
            .about("Controller for in-cluster listening for authentication failures and creates/updates a secret using a refresh token secret created by 'add'")
            .arg(
                Arg::with_name("secret_name")
                    .value_name("SECRET NAME")
                    .help("The name of the dockerconfigjson secret to create/update")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("oauth_scope")
                    .long("oauth-scope")
                    .value_name("SCOPE")
                    .takes_value(true)
                    .default_value(crate::oauth::GCRCRED_HELPER_SCOPE)
                    .hidden(true)
                    .help("The token scope to request"),
            )
            .arg(
                Arg::with_name("oauth_client_id")
                    .long("oauth-client-id")
                    .value_name("ID")
                    .takes_value(true)
                    .requires_all(&["client_secret", "username"])
                    .hidden(true)
                    .help("The client_id to be used when performing the OAuth2 Authorization Code grant flow."),
            )
            .arg(
                Arg::with_name("oauth_client_secret")
                    .long("oauth-client-secret")
                    .value_name("NAME")
                    .takes_value(true)
                    .hidden(true)
                    .help("The client_secret to be used when performing the OAuth2 Authorization Code grant flow."),
            )
            .arg(
                Arg::with_name("oauth_username")
                    .long("oauth-username")
                    .value_name("NAME")
                    .takes_value(true)
                    .hidden(true)
                    .help("The username to pair with the authorization code"),
            )
    }
    /// Main entry point for the watcher
    pub async fn run(
        client: APIClient,
        targets: Targets,
        matches: &ArgMatches<'_>,
    ) -> anyhow::Result<()> {
        let runner = Runner {
            client,
            targets,
            secret_name: matches.value_of("secret_name").expect("SECRET NAME"),
            scope: matches.value_of("oauth_scope").expect("SCOPE"),
            client_id: matches.value_of("oauth_client_id"),
            client_secret: matches.value_of("oauth_client_secret"),
            username: matches.value_of("oauth_username"),
        };
        info!("Target secret: {}", runner.secret_name);
        // Follow the resource in all namespaces
        let resource = Resource::all::<Event>();

        // Create our informer and start listening
        let lp = ListParams::default();
        let ei = Informer::new(runner.client.clone(), lp, resource);
        loop {
            while let Some(event) = ei.poll().await?.boxed().try_next().await? {
                runner.handle(event).await?;
            }
        }
    }

    fn refresh_token_name(&self) -> String {
        format!("{}-refresh-token", self.secret_name)
    }

    async fn refresh_token(&self) -> anyhow::Result<RefreshToken> {
        let secret_name = self.refresh_token_name();
        info!("Fetching referesh token from {}", secret_name);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.targets.namespace());
        if let Ok(secret) = secrets.get(&secret_name).await {
            if secret.data.is_none() {
                Err(anyhow!(
                    "Refresh token secret {} is missing data entry",
                    secret_name
                ))
            } else if let Some(token) = secret.data.unwrap().get("refresh_token") {
                let token = String::from_utf8(token.0.clone())?;
                Ok(RefreshToken::new(token))
            } else {
                Err(anyhow!(
                    "Refresh token secret {} is missing its token",
                    secret_name
                ))
            }
        } else {
            Err(anyhow!("Refresh token {} is missing", secret_name))
        }
    }

    /// Event handler
    async fn handle(&self, event: WatchEvent<Event>) -> anyhow::Result<()> {
        match event {
            WatchEvent::Added(event) => {
                if Watcher::is_recent_gcr_auth_failure(&event) {
                    info!("{}", event.message.unwrap_or_else(|| "".into()));
                    let refresh_token = self.refresh_token().await?;
                    let token_response = crate::oauth::refresh(
                        self.client_id,
                        self.client_secret,
                        self.scope,
                        &refresh_token,
                    )?;
                    Credentials::from_access_token(token_response.access_token(), self.username)
                        .as_secret(self.into())
                        .upsert(&self.client, self.targets.namespace(), self.secret_name)
                        .await
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}
