use anyhow::anyhow;
use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, LocalObjectReference, PodSpec, PodTemplateSpec, Secret, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, PolicyRule, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::api::{ObjectMeta, PostParams};
use kube::client::APIClient;
use kube::Api;
use oauth2::basic::BasicTokenResponse;
use oauth2::prelude::SecretNewType;
use oauth2::prelude::*;
use oauth2::{AuthorizationCode, CsrfToken, RedirectUrl, RefreshToken, TokenResponse};
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use tokio::io::stdin;
use tokio::net::TcpListener;
use tokio::prelude::*;
use tokio::stream::StreamExt;
use tokio_util::codec::{FramedRead, LinesCodec};
use url::Url;

use crate::common::KubeCrud;
use crate::{CredentialConfiguration, Credentials, Targets};

pub struct Setup<'a> {
    client: APIClient,
    targets: Targets,
    secret_name: &'a str,
    service_account: Vec<&'a str>,
    controller_image: String,
    scope: &'a str,
    client_id: Option<&'a str>,
    client_secret: Option<&'a str>,
    username: Option<&'a str>,
}

impl<'a> From<&'a Setup<'a>> for CredentialConfiguration<'a> {
    fn from(w: &'a Setup<'a>) -> Self {
        CredentialConfiguration::new(w.secret_name, &w.targets)
    }
}

lazy_static! {
    static ref DEFAULT_CONTROLLER_IMAGE: String = format!(
        "stephenc/{}:{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
}

impl Setup<'_> {
    const REDIRECT_URIAUTH_CODE_IN_TITLE_BAR: &'static str = "urn:ietf:wg:oauth:2.0:oob";

    pub fn add_subcommand(name: &str) -> App {
        SubCommand::with_name(name)
            .about("Adds an in-cluster refresh service")
            .arg(
                Arg::with_name("secret_name")
                    .value_name("SECRET NAME")
                    .help("The name of the managed dockerconfigjson secret")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("no_browser")
                    .long("no-browser")
                    .help("Forbid automatic browser launch"),
            )
            .arg(
                Arg::with_name("force_auth")
                    .long("force-auth-refresh")
                    .help("Force renewal of the refresh token even if already configured"),
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
            .group(ArgGroup::with_name("oauth").args(&["oauth_scope", "oauth_client_id", "oauth_client_secret", "oauth_username"]))
            .arg(
                Arg::with_name("service_account")
                    .long("service-account")
                    .value_name("NAME")
                    .multiple(true)
                    .number_of_values(1)
                    .default_value("default")
                    .help("The service account to update the imagePullSecrets of"),
            )
            .arg(
                Arg::with_name("controller_image")
                    .long("controller-image")
                    .value_name("IMAGE")
                    .takes_value(true)
                    .default_value(DEFAULT_CONTROLLER_IMAGE.as_ref())
                    .help("The controller image to use"),
            )
    }
    pub fn remove_subcommand(name: &str) -> App {
        SubCommand::with_name(name)
            .about("Removes an in-cluster refresh service")
            .arg(
                Arg::with_name("secret_name")
                    .value_name("SECRET NAME")
                    .help("The name of the managed dockerconfigjson secret")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::with_name("service_account")
                    .long("service-account")
                    .value_name("NAME")
                    .multiple(true)
                    .number_of_values(1)
                    .default_value("default")
                    .help("The service account to update the imagePullSecrets of"),
            )
    }

    pub async fn add(
        client: APIClient,
        targets: Targets,
        matches: &ArgMatches<'_>,
    ) -> anyhow::Result<()> {
        let no_browser = matches.is_present("no_browser");
        let force_auth = matches.is_present("force_auth");

        Setup {
            client,
            targets,
            secret_name: matches.value_of("secret_name").expect("SECRET NAME"),
            service_account: matches
                .values_of("service_account")
                .map(|i| i.collect())
                .unwrap_or_else(|| vec!["default"]),
            controller_image: matches
                .value_of("controller_image")
                .map(String::from)
                .unwrap_or_else(|| DEFAULT_CONTROLLER_IMAGE.clone()),
            scope: matches
                .value_of("oauth_scope")
                .unwrap_or(crate::oauth::GCRCRED_HELPER_SCOPE),
            client_id: matches.value_of("oauth_client_id"),
            client_secret: matches.value_of("oauth_client_secret"),
            username: matches.value_of("oauth_username"),
        }
        .do_add(no_browser, force_auth)
        .await
    }

    async fn do_add(self, no_browser: bool, force_auth: bool) -> anyhow::Result<()> {
        debug!("Target secret: {}", self.secret_name);

        if force_auth || self.is_existing_refresh_valid().await? {
            debug!("Getting refresh token");
            let token = self.request_token_interactive(no_browser).await?;
            debug!(
                "Upserting refresh token secret {}",
                self.refresh_token_name()
            );
            self.as_secret(&token)
                .upsert(&self.client, self.namespace(), &self.refresh_token_name())
                .await?;
            debug!("Upserting secret {}", self.secret_name);
            Credentials::from_access_token(token.access_token(), self.username)
                .as_secret((&self).into())
                .upsert(&self.client, self.namespace(), self.secret_name)
                .await?;
        }
        debug!(
            "Upserting controller service account {}",
            self.service_account_name()
        );
        self.as_service_account()
            .upsert(
                &self.client,
                &self.namespace(),
                &self.service_account_name(),
            )
            .await?;
        debug!("Upserting cluster role {}", self.cluster_role_name());
        self.as_cluster_role()
            .upsert(&self.client, self.namespace(), &self.cluster_role_name())
            .await?;
        debug!(
            "Upserting cluster role binding {}",
            self.cluster_role_binding_name()
        );
        self.as_cluster_role_binding()
            .upsert(
                &self.client,
                self.namespace(),
                &self.cluster_role_binding_name(),
            )
            .await?;
        debug!("Upserting controller deployment {}", self.controller_name());
        self.as_deployment()
            .upsert(&self.client, self.namespace(), &self.controller_name())
            .await?;
        for &service_account in self.service_account.iter() {
            debug!(
                "Adding imagePullSecret to service account {}",
                service_account
            );
            self.update_service_account(service_account.into(), true)
                .await?;
        }
        info!("GCR authentication helper {} added", self.secret_name);
        Ok(())
    }

    pub async fn remove(
        client: APIClient,
        targets: Targets,
        matches: &ArgMatches<'_>,
    ) -> anyhow::Result<()> {
        Setup {
            client,
            targets,
            secret_name: matches.value_of("secret_name").expect("SECRET NAME"),
            service_account: matches
                .values_of("service_account")
                .map(|i| i.collect())
                .unwrap_or_else(|| vec!["default"]),
            controller_image: DEFAULT_CONTROLLER_IMAGE.clone(),
            // remaining values are irrelevant as we are removing the refresh service
            scope: crate::oauth::GCRCRED_HELPER_SCOPE,
            client_id: None,
            client_secret: None,
            username: None,
        }
        .do_remove()
        .await
    }

    async fn do_remove(self) -> anyhow::Result<()> {
        debug!("Target secret: {}", self.secret_name);
        for &service_account in self.service_account.iter() {
            debug!(
                "Removing imagePullSecret from service account {}",
                service_account
            );
            self.update_service_account(service_account.into(), false)
                .await?;
        }
        debug!("Deleting controller deployment {}", self.controller_name());
        Deployment::delete(&self.client, self.namespace(), &self.controller_name()).await?;
        debug!(
            "Deleting cluster role binding {}",
            self.cluster_role_binding_name()
        );
        ClusterRoleBinding::delete(
            &self.client,
            self.namespace(),
            &self.cluster_role_binding_name(),
        )
        .await?;
        debug!("Deleting cluster role {}", self.cluster_role_name());
        ClusterRole::delete(&self.client, self.namespace(), &self.cluster_role_name()).await?;
        debug!(
            "Deleting controller service account {}",
            self.service_account_name()
        );
        ServiceAccount::delete(&self.client, self.namespace(), &self.service_account_name())
            .await?;
        debug!("Deleting secret {}", self.secret_name);
        Secret::delete(&self.client, self.namespace(), self.secret_name).await?;
        debug!(
            "Deleting refresh token secret {}",
            self.refresh_token_name()
        );
        Secret::delete(&self.client, self.namespace(), &self.refresh_token_name()).await?;
        info!("GCR authentication helper {} removed", self.secret_name);
        Ok(())
    }

    fn namespace(&self) -> &str {
        self.targets.namespace()
    }

    fn refresh_token_name(&self) -> String {
        format!("{}-refresh-token", self.secret_name)
    }

    fn controller_name(&self) -> String {
        format!("{}-refresh-service", self.secret_name)
    }

    fn service_account_name(&self) -> String {
        format!("{}-refresh-service", self.secret_name)
    }

    fn cluster_role_name(&self) -> String {
        format!(
            "{}:{}:{}-refresh",
            self.namespace(),
            env!("CARGO_PKG_NAME").to_string(),
            self.secret_name
        )
    }

    fn cluster_role_binding_name(&self) -> String {
        format!(
            "{}:{}:{}-refresh",
            self.namespace(),
            env!("CARGO_PKG_NAME").to_string(),
            self.secret_name
        )
    }

    async fn update_service_account(
        &self,
        name: String,
        include_pull_secret: bool,
    ) -> anyhow::Result<()> {
        let pp = PostParams::default();
        let objects: Api<ServiceAccount> = Api::namespaced(self.client.clone(), self.namespace());
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
                                self.secret_name != n
                            } else {
                                true
                            }
                        }) {
                            v.push(x.clone())
                        }
                        if v.is_empty() {
                            None
                        } else {
                            Some(v)
                        }
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

    async fn is_existing_refresh_valid(&self) -> anyhow::Result<bool> {
        match self.fetch_refresh_token().await {
            Ok(refresh_token) => {
                match crate::oauth::refresh(
                    self.client_id,
                    self.client_secret,
                    self.scope,
                    &refresh_token,
                ) {
                    Ok(token_response) => {
                        debug!("Upserting secret {}", self.secret_name);
                        Credentials::from_access_token(
                            token_response.access_token(),
                            self.username,
                        )
                        .as_secret(self.into())
                        .upsert(&self.client, self.namespace(), self.secret_name)
                        .await?;
                        Ok(false)
                    }
                    Err(_) => {
                        warn!("Existing refresh token is no longer valid");
                        Ok(true)
                    }
                }
            }
            Err(_) => Ok(true),
        }
    }

    async fn fetch_refresh_token(&self) -> anyhow::Result<RefreshToken> {
        let secret_name = self.refresh_token_name();
        debug!("Fetching referesh token from {}", secret_name);
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace());
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

    /// Converts the refresh token into a named secret for the specified namespace.
    fn as_secret(&self, token: &BasicTokenResponse) -> Secret {
        Secret {
            metadata: Some(ObjectMeta {
                name: Some(self.refresh_token_name()),
                namespace: Some(self.namespace().into()),
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
                namespace: Some(self.namespace().into()),
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
                            command: Some({
                                let mut c = vec![
                                    format!("/{}", env!("CARGO_PKG_NAME")),
                                    "--in-cluster".to_string(),
                                    "--namespace".to_string(),
                                    self.namespace().to_string(),
                                ];
                                for url in self.targets.registry_urls().iter() {
                                    c.push("--registry-url".to_string());
                                    c.push((*url).to_string());
                                }
                                c.push("run".to_string());
                                c.push(self.secret_name.to_string());
                                c
                            }),
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
                namespace: Some(self.namespace().into()),
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
                    verbs: vec!["create".to_string()],
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".to_string()]),
                    resources: Some(vec!["secrets".to_string()]),
                    verbs: vec![
                        "get".to_string(),
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
                namespace: Some(self.namespace().into()),
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

        let client = crate::oauth::new_client(self.client_id, self.client_secret, self.scope)
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
        client
            .exchange_code(code)
            .map_err(crate::oauth::map_oauth_err)
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
