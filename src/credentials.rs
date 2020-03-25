use k8s_openapi::api::core::v1::Secret;
use kube::api::ObjectMeta;
use oauth2::prelude::*;
use oauth2::AccessToken;
use serde_derive::{Deserialize, Serialize};
use serde_json::json;
use std::process::Stdio;
use tokio::prelude::*;
use tokio::process::Command;

/// The credentials returned as JSON by a docker credentials helper command.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Credentials {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Secret")]
    secret: String,
}

pub trait K8sImagePullSecret {
    fn registry_url(&self) -> &str;
    fn namespace(&self) -> &str;
    fn name(&self) -> &str;
}

impl Credentials {
    /// Constructs a new instance by forking a `gcloud` child process.
    pub async fn from_gcloud(registry_url: &str) -> anyhow::Result<Self> {
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
            .write_all(registry_url.as_bytes())
            .await?;
        serde_json::from_slice(&child.wait_with_output().await?.stdout).map_err(|e| e.into())
    }

    /// Constructs a new instance from an access token
    pub fn from_access_token(token: &AccessToken) -> Self {
        Credentials {
            // we have to impersonate https://github.com/GoogleCloudPlatform/docker-credential-gcr/
            username: "_dcgcr_2_0_1_token".into(),
            secret: token.secret().into(),
        }
    }

    /// Converts the credentials into a named secret for the specified namespace.
    pub fn as_secret(&self, details: &dyn K8sImagePullSecret) -> Secret {
        Secret {
            metadata: Some(ObjectMeta {
                name: Some(details.name().into()),
                namespace: Some(details.namespace().into()),
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
                    json!({
                    "auths": {
                        details.registry_url(): {
                            "username": self.username.clone(),
                            "password": self.secret.clone(),
                            "auths": base64::encode(format!("{}:{}", self.username, self.secret))
                        }
                    }
                }).to_string()
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        }
    }

    /// Converts the credentials into the byte array of its Secret form serialized as JSON.
    pub fn as_secret_bytes(&self, details: &dyn K8sImagePullSecret) -> Vec<u8> {
        serde_json::to_string(&self.as_secret(details))
            .unwrap()
            .into_bytes()
    }
}
