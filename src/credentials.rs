use std::collections::BTreeMap;
use std::process::Stdio;

use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use oauth2::prelude::*;
use oauth2::AccessToken;
use serde_derive::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::prelude::*;
use tokio::process::Command;

use crate::Targets;

/// The credentials returned as JSON by a docker credentials helper command.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Credentials {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Secret")]
    secret: String,
}

pub struct CredentialConfiguration<'a> {
    secret_name: &'a str,
    targets: &'a Targets,
}

impl<'a> CredentialConfiguration<'a> {
    pub fn new(secret_name: &'a str, targets: &'a Targets) -> CredentialConfiguration<'a> {
        CredentialConfiguration {
            secret_name,
            targets,
        }
    }
}

pub trait K8sImagePullSecret {
    fn registry_url(&self) -> &str;
    fn namespace(&self) -> &str;
    fn name(&self) -> &str;
    fn targets(&self) -> &Targets;
}

impl Credentials {
    /// Constructs a new instance by forking a `gcloud` child process.
    pub async fn from_gcloud() -> anyhow::Result<Self> {
        let mut child = Command::new("gcloud")
            .arg("auth")
            .arg("docker-helper")
            .arg("get")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"https://gcr.io") // url does not matter, same token used for all
            .await?;
        serde_json::from_slice(&child.wait_with_output().await?.stdout).map_err(|e| e.into())
    }

    /// Constructs a new instance from an access token
    pub fn from_access_token(token: &AccessToken, username: Option<&str>) -> Self {
        Credentials {
            // we have to impersonate https://github.com/GoogleCloudPlatform/docker-credential-gcr/
            username: username.unwrap_or("_dcgcr_2_0_1_token").into(),
            secret: token.secret().into(),
        }
    }

    /// Converts the credentials into a named secret for the specified namespace.
    pub fn as_secret(&self, config: CredentialConfiguration<'_>) -> Secret {
        let auths: BTreeMap<String, Value> = config
            .targets
            .registry_urls()
            .iter()
            .map(|url| {
                (
                    (*url).to_string(),
                    json! {
                        {
                            "username": self.username.clone(),
                            "password": self.secret.clone(),
                            "auths": base64::encode(format!("{}:{}", self.username, self.secret))
                        }
                    },
                )
            })
            .collect();
        Secret {
            metadata: Some(ObjectMeta {
                name: Some(config.secret_name.into()),
                namespace: Some(config.targets.namespace().into()),
                labels: Some(
                    vec![
                        (
                            "app.kubernetes.io/name".to_string(),
                            env!("CARGO_PKG_NAME").to_string(),
                        ),
                        (
                            "app.kubernetes.io/version".to_string(),
                            env!("CARGO_PKG_VERSION").to_string(),
                        ),
                        (
                            "app.kubernetes.io/component".to_string(),
                            "dockerconfigjson".to_string(),
                        ),
                        (
                            "app.kubernetes.io/managed-by".to_string(),
                            env!("CARGO_PKG_NAME").to_string(),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
                ..Default::default()
            }),
            type_: Some("kubernetes.io/dockerconfigjson".into()),
            string_data: Some(
                vec![(
                    ".dockerconfigjson".to_string(),
                    json!({ "auths": auths }).to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        }
    }

    /// Converts the credentials into the byte array of its Secret form serialized as JSON.
    pub fn as_secret_bytes(&self, config: CredentialConfiguration<'_>) -> Vec<u8> {
        serde_json::to_string(&self.as_secret(config))
            .unwrap()
            .into_bytes()
    }
}
