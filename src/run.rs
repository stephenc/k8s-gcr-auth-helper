use crate::credentials::K8sImagePullSecret;
use crate::{Credentials, Setup, Watcher};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event, Secret};
use kube::api::{ListParams, PostParams, WatchEvent};
use kube::client::APIClient;
use kube::runtime::Informer;
use kube::{Api, Resource};

use oauth2::prelude::*;
use oauth2::{RefreshToken, Scope, TokenResponse};

use anyhow::anyhow;

pub struct Runner<'a> {
    client: APIClient,
    registry_url: &'a str,
    namespace: &'a str,
    secret_name: &'a str,
}

impl K8sImagePullSecret for Runner<'_> {
    fn registry_url(&self) -> &str {
        self.registry_url
    }

    fn namespace(&self) -> &str {
        self.namespace
    }

    fn name(&self) -> &str {
        self.secret_name
    }
}

impl Runner<'_> {
    /// Main entry point for the watcher
    pub async fn run(
        client: APIClient,
        registry_url: &str,
        namespace: &str,
        secret_name: &str,
    ) -> anyhow::Result<()> {
        info!("Target secret: {}", secret_name);
        let runner = Runner {
            client,
            registry_url,
            namespace,
            secret_name,
        };
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
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
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
                    let client = Setup::new_basic_client();
                    let token_response = client
                        .add_scope(Scope::new(
                            "https://www.googleapis.com/auth/cloud-platform".to_string(),
                        ))
                        .exchange_refresh_token(&refresh_token)
                        .map_err(Setup::map_oauth_err)?;
                    let access_token = token_response.access_token();
                    let credentials = Credentials::from_access_token(access_token);
                    let data = credentials.as_secret_bytes(self);
                    let pp = PostParams::default();
                    let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
                    if secrets.get(self.secret_name).await.is_ok() {
                        secrets.replace(self.secret_name, &pp, data).await?;
                        info!("Secret {} updated", self.secret_name);
                    } else {
                        secrets.create(&pp, data).await?;
                        info!("Secret {} created", self.secret_name);
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
