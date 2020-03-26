use std::borrow::BorrowMut;
use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, LocalObjectReference, PodSpec, PodTemplateSpec, Secret, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::client::APIClient;
use kube::Api;
use oauth2::basic::{BasicClient, BasicErrorResponseType, BasicTokenResponse};
use oauth2::prelude::SecretNewType;
use oauth2::prelude::*;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RequestTokenError,
    Scope, TokenResponse, TokenUrl,
};
use tokio::io::stdin;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use url::Url;

use anyhow::anyhow;

use crate::credentials::K8sImagePullSecret;
use crate::Credentials;

pub struct Setup<'a> {
    client: APIClient,
    registry_url: &'a str,
    namespace: &'a str,
    secret_name: &'a str,
    scope: &'a str,
    service_account: &'a str,
    controller_image: String,
}

impl K8sImagePullSecret for Setup<'_> {
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

impl Setup<'_> {
    // NOTE: GCRCREDs "borrowed" from https://github.com/GoogleCloudPlatform/docker-credential-gcr/
    // as they are the only ones that work with any localhost URL

    /// GCRCRED_HELPER_CLIENT_ID is the client_id to be used when performing the
    /// OAuth2 Authorization Code grant flow.
    /// See https://developers.google.com/identity/protocols/OAuth2InstalledApp
    const GCRCRED_HELPER_CLIENT_ID: &'static str =
        "99426463878-o7n0bshgue20tdpm25q4at0vs2mr4utq.apps.googleusercontent.com";

    /// GCRCRED_HELPER_CLIENT_NOT_SO_SECRET is the client_secret to be used when
    /// performing the OAuth2 Authorization Code grant flow.
    /// See https://developers.google.com/identity/protocols/OAuth2InstalledApp
    const GCRCRED_HELPER_CLIENT_NOT_SO_SECRET: &'static str = "HpVi8cnKx8AAkddzaNrSWmS8";

    const GCRCRED_HELPER_SCOPE: &'static str = "https://www.googleapis.com/auth/cloud-platform";

    const REDIRECT_URIAUTH_CODE_IN_TITLE_BAR: &'static str = "urn:ietf:wg:oauth:2.0:oob";

    pub fn default_controller_image() -> String {
        format!(
            "stephenc/{}:{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
    }

    pub async fn add(
        client: APIClient,
        registry_url: &str,
        namespace: &str,
        secret_name: &str,
        no_browser: bool,
        force_auth: bool,
        scope: Option<&str>,
        service_account: Option<&str>,
        controller_image: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!("Target secret: {}", secret_name);
        let runner = Setup {
            client,
            registry_url,
            namespace,
            secret_name,
            scope: scope.unwrap_or(Self::GCRCRED_HELPER_SCOPE),
            service_account: service_account.unwrap_or("default"),
            controller_image: controller_image
                .map(String::from)
                .unwrap_or_else(Self::default_controller_image),
        };

        if force_auth || !runner.is_secret_exist(runner.secret_name.into()).await? {
            debug!("Getting refresh token");
            let token = runner.request_token_interactive(no_browser).await?;
            debug!(
                "Upserting refresh token secret {}",
                runner.refresh_token_name()
            );
            runner
                .upsert_secret(runner.refresh_token_name(), runner.as_secret_bytes(&token))
                .await?;
            debug!("Upserting secret {}", runner.secret_name);
            runner
                .upsert_secret(
                    runner.secret_name.into(),
                    Credentials::from_access_token(token.access_token()).as_secret_bytes(&runner),
                )
                .await?;
        }
        debug!(
            "Upserting controller service account {}",
            runner.service_account_name()
        );
        runner
            .upsert_service_account(runner.service_account_name(), runner.as_service_account())
            .await?;
        debug!("Upserting cluster role {}", runner.cluster_role_name());
        runner
            .upsert_cluster_role(runner.cluster_role_name(), runner.as_cluster_role())
            .await?;
        debug!(
            "Upserting cluster role binding {}",
            runner.cluster_role_binding_name()
        );
        runner
            .upsert_cluster_role_binding(
                runner.cluster_role_binding_name(),
                runner.as_cluster_role_binding(),
            )
            .await?;
        debug!(
            "Upserting controller deployment {}",
            runner.controller_name()
        );
        runner
            .upsert_delpoyment(runner.controller_name(), runner.as_deployment())
            .await?;
        if !runner.service_account.is_empty() {
            debug!("Adding imagePullSecret to service account {}", "default");
            runner
                .update_service_account("default".into(), true)
                .await?;
        }
        Ok(())
    }

    pub async fn remove(
        client: APIClient,
        registry_url: &str,
        namespace: &str,
        secret_name: &str,
        service_account: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!("Target secret: {}", secret_name);
        let runner = Setup {
            client,
            registry_url,
            namespace,
            secret_name,
            scope: Self::GCRCRED_HELPER_SCOPE,
            service_account: service_account.unwrap_or("default"),
            controller_image: Self::default_controller_image(),
        };

        if !runner.service_account.is_empty() {
            debug!(
                "Removing imagePullSecret from service account {}",
                "default"
            );
            runner
                .update_service_account("default".into(), false)
                .await?;
        }
        debug!(
            "Deleting controller deployment {}",
            runner.controller_name()
        );
        runner.delete_deployment(runner.controller_name()).await?;
        debug!(
            "Deleting cluster role binding {}",
            runner.cluster_role_binding_name()
        );
        runner
            .delete_cluster_role_binding(runner.cluster_role_binding_name())
            .await?;
        debug!("Deleting cluster role {}", runner.cluster_role_name());
        runner
            .delete_cluster_role(runner.cluster_role_name())
            .await?;
        debug!(
            "Deleting controller service account {}",
            runner.service_account_name()
        );
        runner
            .delete_service_account(runner.service_account_name())
            .await?;
        debug!("Deleting secret {}", runner.secret_name);
        runner.delete_secret(runner.secret_name.into()).await?;
        debug!(
            "Deleting refresh token secret {}",
            runner.refresh_token_name()
        );
        runner.delete_secret(runner.refresh_token_name()).await?;
        Ok(())
    }

    fn refresh_token_name(&self) -> String {
        format!("{}-refresh-token", self.secret_name)
    }

    fn controller_name(&self) -> String {
        format!("{}-controller", self.secret_name)
    }

    fn service_account_name(&self) -> String {
        format!("{}-service-account", self.secret_name)
    }

    fn cluster_role_name(&self) -> String {
        format!(
            "{}:{}:{}",
            self.namespace,
            env!("CARGO_PKG_NAME").to_string(),
            self.secret_name
        )
    }

    fn cluster_role_binding_name(&self) -> String {
        format!(
            "{}:{}:{}",
            self.namespace,
            env!("CARGO_PKG_NAME").to_string(),
            self.secret_name
        )
    }

    async fn upsert_cluster_role_binding(
        &self,
        name: String,
        object: ClusterRoleBinding,
    ) -> anyhow::Result<()> {
        let data = serde_json::to_vec(&object).unwrap();
        let pp = PostParams::default();
        let objects: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        if objects.get(&name).await.is_ok() {
            objects.replace(&name, &pp, data).await?;
            debug!("ClusterRoleBinding {} updated", name);
        } else {
            objects.create(&pp, data).await?;
            debug!("ClusterRoleBinding {} created", name);
        }
        Ok(())
    }

    async fn delete_cluster_role_binding(&self, name: String) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ClusterRoleBinding {} deleted", name);
        }
        Ok(())
    }

    async fn upsert_cluster_role(&self, name: String, object: ClusterRole) -> anyhow::Result<()> {
        let data = serde_json::to_vec(&object).unwrap();
        let pp = PostParams::default();
        let objects: Api<ClusterRole> = Api::all(self.client.clone());
        if objects.get(&name).await.is_ok() {
            objects.replace(&name, &pp, data).await?;
            debug!("ClusterRole {} updated", name);
        } else {
            objects.create(&pp, data).await?;
            debug!("ClusterRole {} created", name);
        }
        Ok(())
    }

    async fn delete_cluster_role(&self, name: String) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ClusterRole> = Api::all(self.client.clone());
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ClusterRole {} deleted", name);
        }
        Ok(())
    }

    async fn upsert_service_account(
        &self,
        name: String,
        object: ServiceAccount,
    ) -> anyhow::Result<()> {
        let data = serde_json::to_vec(&object).unwrap();
        let pp = PostParams::default();
        let objects: Api<ServiceAccount> = Api::namespaced(self.client.clone(), self.namespace);
        if objects.get(&name).await.is_ok() {
            objects.replace(&name, &pp, data).await?;
            debug!("ServiceAccount {} updated", name);
        } else {
            objects.create(&pp, data).await?;
            debug!("ServiceAccount {} created", name);
        }
        Ok(())
    }

    async fn update_service_account(
        &self,
        name: String,
        include_pull_secret: bool,
    ) -> anyhow::Result<()> {
        let pp = PostParams::default();
        let objects: Api<ServiceAccount> = Api::namespaced(self.client.clone(), self.namespace);
        if let Ok(service_account) = objects.get(&name).await {
            let service_account = ServiceAccount {
                image_pull_secrets: match &service_account.image_pull_secrets {
                    Some(vec) => {
                        let mut v: Vec<LocalObjectReference> = Vec::new();
                        if include_pull_secret {
                            v.push(LocalObjectReference {
                                name: Some(self.secret_name.into()),
                            });
                        }
                        for x in vec.iter().filter(|x| {
                            if let Some(n) = &x.name {
                                &name != n
                            } else {
                                true
                            }
                        }) {
                            v.push(x.clone())
                        }
                        Some(v)
                    }
                    None => Some(vec![LocalObjectReference {
                        name: Some(self.secret_name.into()),
                    }]),
                },
                ..service_account
            };
            let data = serde_json::to_vec(&service_account).unwrap();
            objects.replace(&name, &pp, data).await?;
            debug!("ServiceAccount {} updated", name);
        }
        Ok(())
    }

    async fn delete_service_account(&self, name: String) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<ServiceAccount> = Api::namespaced(self.client.clone(), self.namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("ServiceAccount {} deleted", name);
        }
        Ok(())
    }

    async fn upsert_delpoyment(
        &self,
        deployment_name: String,
        deployment: Deployment,
    ) -> anyhow::Result<()> {
        let data = serde_json::to_vec(&deployment).unwrap();
        let pp = PostParams::default();
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), self.namespace);
        if deployments.get(&deployment_name).await.is_ok() {
            deployments.replace(&deployment_name, &pp, data).await?;
            debug!("Deployment {} updated", deployment_name);
        } else {
            deployments.create(&pp, data).await?;
            debug!("Deployment {} created", deployment_name);
        }
        Ok(())
    }

    async fn delete_deployment(&self, name: String) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<Deployment> = Api::namespaced(self.client.clone(), self.namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("Deployment {} deleted", name);
        }
        Ok(())
    }

    async fn is_secret_exist(&self, secret_name: String) -> anyhow::Result<bool> {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        Ok(secrets.get(&secret_name).await.is_ok())
    }

    async fn upsert_secret(&self, secret_name: String, data: Vec<u8>) -> anyhow::Result<()> {
        let pp = PostParams::default();
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        if secrets.get(&secret_name).await.is_ok() {
            secrets.replace(&secret_name, &pp, data).await?;
            debug!("Secret {} updated", secret_name);
        } else {
            secrets.create(&pp, data).await?;
            debug!("Secret {} created", secret_name);
        }
        Ok(())
    }

    async fn delete_secret(&self, name: String) -> anyhow::Result<()> {
        let dp = DeleteParams::default();
        let objects: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
        if objects.delete(&name, &dp).await.is_ok() {
            debug!("Secret {} deleted", name);
        }
        Ok(())
    }

    /// Converts the refresh token into a named secret for the specified namespace.
    fn as_secret(&self, token: &BasicTokenResponse) -> Secret {
        Secret {
            metadata: Some(ObjectMeta {
                name: Some(self.refresh_token_name()),
                namespace: Some(self.namespace.into()),
                labels: Some(self.labels("refresh-token")),
                ..Default::default()
            }),
            type_: Some("Opaque".into()),
            string_data: Some(
                vec![(
                    "refresh_token".to_string(),
                    token.refresh_token().unwrap().secret().to_string(),
                )]
                .into_iter()
                .collect(),
            ),
            ..Default::default()
        }
    }

    /// Converts the credentials into the byte array of its Secret form serialized as JSON.
    pub fn as_secret_bytes(&self, token: &BasicTokenResponse) -> Vec<u8> {
        serde_json::to_string(&self.as_secret(token))
            .unwrap()
            .into_bytes()
    }

    fn labels(&self, component: &str) -> BTreeMap<String, String> {
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
                component.to_string(),
            ),
            (
                "app.kubernetes.io/managed-by".to_string(),
                env!("CARGO_PKG_NAME").to_string(),
            ),
        ]
        .into_iter()
        .collect()
    }

    fn as_deployment(&self) -> Deployment {
        let labels = self.labels("controller");
        Deployment {
            metadata: Some(ObjectMeta {
                name: Some(self.controller_name()),
                namespace: Some(self.namespace.into()),
                labels: Some(labels.clone()),
                ..Default::default()
            }),
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                selector: LabelSelector {
                    match_labels: Some(labels.clone()),
                    ..Default::default()
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        service_account_name: Some(self.service_account_name()),
                        containers: vec![Container {
                            image: Some(self.controller_image.to_string()),
                            name: self.controller_name(),
                            command: Some(vec![
                                format!("/{}", env!("CARGO_PKG_NAME")),
                                "--in-cluster".to_string(),
                                "--namespace".to_string(),
                                self.namespace.to_string(),
                                "--registry-url".to_string(),
                                self.registry_url.to_string(),
                                "run".to_string(),
                                self.secret_name.to_string(),
                            ]),
                            ..Default::default()
                        }],
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn as_service_account(&self) -> ServiceAccount {
        ServiceAccount {
            metadata: Some(ObjectMeta {
                name: Some(self.service_account_name()),
                namespace: Some(self.namespace.into()),
                labels: Some(self.labels("serviceaccount")),
                ..Default::default()
            }),
            automount_service_account_token: Some(true),
            ..Default::default()
        }
    }

    fn as_cluster_role(&self) -> ClusterRole {
        ClusterRole {
            metadata: Some(ObjectMeta {
                name: Some(self.cluster_role_name()),
                labels: Some(self.labels("clusterrole")),
                ..Default::default()
            }),
            rules: Some(vec![
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string()]),
                    verbs: vec![
                        "get".to_string(),
                        "create".to_string(),
                        "delete".to_string(),
                        "patch".to_string(),
                        "list".to_string(),
                        "update".to_string(),
                    ],
                    resource_names: Some(vec![self.secret_name.to_string()]),
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string()]),
                    verbs: vec!["get".to_string(), "list".to_string(), "view".to_string()],
                    resource_names: Some(vec![self.refresh_token_name()]),
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["events".to_string()]),
                    verbs: vec!["get".to_string(), "list".to_string(), "watch".to_string()],
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }
    }

    fn as_cluster_role_binding(&self) -> ClusterRoleBinding {
        ClusterRoleBinding {
            metadata: Some(ObjectMeta {
                name: Some(self.cluster_role_binding_name()),
                labels: Some(self.labels("clusterrolebinding")),
                ..Default::default()
            }),
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".into(),
                name: self.cluster_role_name(),
                kind: "ClusterRole".into(),
            },
            subjects: Some(vec![Subject {
                kind: "ServiceAccount".into(),
                namespace: Some(self.namespace.into()),
                name: self.service_account_name(),
                ..Default::default()
            }]),
        }
    }

    async fn request_token_interactive(
        &self,
        no_browser: bool,
    ) -> anyhow::Result<BasicTokenResponse> {
        let listener = if no_browser {
            None
        } else {
            Some(TcpListener::bind("127.0.0.1:0").await?)
        };
        let redirect_url = match &listener {
            Some(listener) => format!("http://localhost:{}", listener.local_addr()?.port()),
            None => Self::REDIRECT_URIAUTH_CODE_IN_TITLE_BAR.to_string(),
        };

        let client = self
            .new_client()
            .await?
            .set_redirect_url(RedirectUrl::new(Url::parse(&redirect_url)?));

        // This is the URL you should redirect the user to, in order to trigger the authorization
        // process.
        let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random);

        // Send the User to the URL
        if listener.is_none() || webbrowser::open(&auth_url.to_string()).is_err() {
            println!("Please visit the following URL and complete the authorization dialog:");
            println!();
            println!("{}", auth_url);
        }
        // Get the authorization code from the user
        let code = match listener {
            Some(listener) => Self::code_via_browser(listener, csrf_token).await?,
            None => Self::code_via_prompt().await?,
        };
        // Exchange the code with a token.
        client.exchange_code(code).map_err(Self::map_oauth_err)
    }

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

    pub fn new_basic_client() -> BasicClient {
        BasicClient::new(
            ClientId::new(Self::GCRCRED_HELPER_CLIENT_ID.to_string()),
            Some(ClientSecret::new(
                Self::GCRCRED_HELPER_CLIENT_NOT_SO_SECRET.to_string(),
            )),
            AuthUrl::new(Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap()),
            Some(TokenUrl::new(
                Url::parse("https://www.googleapis.com/oauth2/v3/token").unwrap(),
            )),
        )
    }

    async fn new_client(&self) -> anyhow::Result<BasicClient> {
        Ok(Self::new_basic_client().add_scope(Scope::new(self.scope.to_string())))
    }

    async fn code_via_prompt() -> anyhow::Result<AuthorizationCode> {
        println!();
        println!("Authorization code:");
        FramedRead::new(stdin(), LinesCodec::new())
            .try_next()
            .await
            .map_err(|e| e.into())
            .and_then(|code| match code {
                Some(code) => Ok(AuthorizationCode::new(code)),
                _ => Err(anyhow!("No Authorization code provided")),
            })
    }

    async fn code_via_browser(
        mut listener: TcpListener,
        csrf_token: CsrfToken,
    ) -> anyhow::Result<AuthorizationCode> {
        if let Ok(Some(mut stream)) = listener.try_next().await {
            let code;
            let state;
            {
                let request_line = FramedRead::new(stream.borrow_mut(), LinesCodec::new())
                    .try_next()
                    .await
                    .map_err(|e| e.into())
                    .and_then(|line| match line {
                        Some(line) => Ok(line),
                        _ => Err(anyhow!("No HTTP Request Line")),
                    })?;

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url))?;

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }
            let success = state.secret() == csrf_token.secret();
            let (message, status) = if success {
                ("Success! You may now close your browser.", "200 OK")
            } else {
                (
                    "Error! CSRF token did not match, close your browser and try again.",
                    "400 Bad Request",
                )
            };
            let response = format!(
                "HTTP/1.1 {}\r\ncontent-length: {}\r\n\r\n{}",
                status,
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).await?;

            // The server will terminate itself after collecting the first code.
            if success {
                return Ok(code);
            }
        }
        Err(anyhow::anyhow!("No authorization code"))
    }
}
