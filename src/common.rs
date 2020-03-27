use anyhow::Error;
use clap::{Arg, ArgMatches};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use kube::api::{DeleteParams, PostParams};
use kube::client::APIClient;
use kube::Api;

use async_trait::async_trait;

#[derive(Debug, PartialEq, Clone)]
pub struct Targets {
    namespace: String,
    registry_ulrs: Vec<String>,
}

impl Targets {
    pub fn args() -> Vec<Arg<'static, 'static>> {
        vec![
            Arg::with_name("registry_url")
                .multiple(true)
                .short("r")
                .long("registry-url")
                .number_of_values(1)
                .default_value("https://gcr.io")
                .value_name("URL")
                .help("The registry to forward authentication for"),
            Arg::with_name("namespace")
                .short("n")
                .long("namespace")
                .takes_value(true)
                .value_name("NAMESPACE")
                .help("The namespace to create the secret in, if not current namespace"),
        ]
    }

    pub fn new(namespace: &str, registry_urls: &[&str]) -> Self {
        Self {
            namespace: namespace.into(),
            registry_ulrs: registry_urls.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    pub fn from_matches(matches: &ArgMatches, default_namespace: &str) -> Self {
        Self {
            namespace: matches
                .value_of("namespace")
                .map(From::from)
                .unwrap_or_else(|| default_namespace.into()),
            registry_ulrs: matches
                .values_of("registry_url")
                .map(|v| v.map(|s| s.to_string()).collect())
                .unwrap_or_else(Vec::new),
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn registry_urls(&self) -> Vec<&str> {
        self.registry_ulrs.iter().map(AsRef::as_ref).collect()
    }
}

#[async_trait]
pub trait KubeCrud {
    async fn upsert(&self, client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()>;
    async fn delete(client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()>;
}

#[async_trait]
impl KubeCrud for Secret {
    async fn upsert(&self, client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()> {
        let pp = PostParams::default();
        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        if secrets.get(&name).await.is_ok() {
            secrets.replace(&name, &pp, &self).await?;
            debug!("Secret {} updated", name);
        } else {
            secrets.create(&pp, &self).await?;
            debug!("Secret {} created", name);
        }
        Ok(())
    }

    async fn delete(client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<Secret> = Api::namespaced(client.clone(), namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("Secret {} deleted", name);
        }
        Ok(())
    }
}

#[async_trait]
impl KubeCrud for ServiceAccount {
    async fn upsert(&self, client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()> {
        let pp = PostParams::default();
        let accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
        if let Ok(existing) = accounts.get(&name).await {
            let object = self.clone();
            let object = ServiceAccount {
                metadata: object.metadata.or(existing.metadata),
                automount_service_account_token: object
                    .automount_service_account_token
                    .or(existing.automount_service_account_token),
                secrets: object.secrets.or(existing.secrets),
                image_pull_secrets: object.image_pull_secrets.or(existing.image_pull_secrets),
            };
            accounts.replace(&name, &pp, &object).await?;
            debug!("ServiceAccount {} updated", name);
        } else {
            accounts.create(&pp, &self).await?;
            debug!("ServiceAccount {} created", name);
        }
        Ok(())
    }
    async fn delete(client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ServiceAccount {} deleted", name);
        }
        Ok(())
    }
}

#[async_trait]
impl KubeCrud for Deployment {
    async fn upsert(&self, client: &APIClient, namespace: &str, name: &str) -> Result<(), Error> {
        let pp = PostParams::default();
        let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        if deployments.get(&name).await.is_ok() {
            if deployments.replace(&name, &pp, &self).await.is_err() {
                debug!(
                    "Deployment {} cannot be updated, trying to delete and recreate",
                    name
                );
                deployments.delete(&name, &DeleteParams::default()).await?;
                deployments.create(&pp, &self).await?;
            };
            debug!("Deployment {} updated", name);
        } else {
            deployments.create(&pp, &self).await?;
            debug!("Deployment {} created", name);
        }
        Ok(())
    }
    async fn delete(client: &APIClient, namespace: &str, name: &str) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("Deployment {} deleted", name);
        }
        Ok(())
    }
}

#[async_trait]
impl KubeCrud for ClusterRoleBinding {
    async fn upsert(&self, client: &APIClient, _namespace: &str, name: &str) -> Result<(), Error> {
        let pp = PostParams::default();
        let bindings: Api<ClusterRoleBinding> = Api::all(client.clone());
        if bindings.get(&name).await.is_ok() {
            bindings.replace(&name, &pp, &self).await?;
            debug!("ClusterRoleBinding {} updated", name);
        } else {
            bindings.create(&pp, &self).await?;
            debug!("ClusterRoleBinding {} created", name);
        }
        Ok(())
    }
    async fn delete(client: &APIClient, _namespace: &str, name: &str) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ClusterRoleBinding> = Api::all(client.clone());
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ClusterRoleBinding {} deleted", name);
        }
        Ok(())
    }
}

#[async_trait]
impl KubeCrud for ClusterRole {
    async fn upsert(&self, client: &APIClient, _namespace: &str, name: &str) -> Result<(), Error> {
        let pp = PostParams::default();
        let bindings: Api<ClusterRole> = Api::all(client.clone());
        if bindings.get(&name).await.is_ok() {
            bindings.replace(&name, &pp, &self).await?;
            debug!("ClusterRole {} updated", name);
        } else {
            bindings.create(&pp, &self).await?;
            debug!("ClusterRole {} created", name);
        }
        Ok(())
    }
    async fn delete(client: &APIClient, _namespace: &str, name: &str) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ClusterRole> = Api::all(client.clone());
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ClusterRole {} deleted", name);
        }
        Ok(())
    }
}
