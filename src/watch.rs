use crate::credentials::K8sImagePullSecret;
use crate::Credentials;
use chrono::{Duration, Utc};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{Event, Secret};
use kube::api::{ListParams, PostParams, WatchEvent};
use kube::client::APIClient;
use kube::runtime::Informer;
use kube::{Api, Resource};
use regex::Regex;

pub struct Watcher<'a> {
    client: APIClient,
    registry_url: &'a str,
    namespace: &'a str,
    secret_name: &'a str,
}

impl K8sImagePullSecret for Watcher<'_> {
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

impl Watcher<'_> {
    /// Main entry point for the watcher
    pub async fn run(
        client: APIClient,
        registry_url: &str,
        namespace: &str,
        secret_name: &str,
    ) -> anyhow::Result<()> {
        debug!("Target secret: {}", secret_name);
        let runner = Watcher {
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

    /// Event handler
    async fn handle(&self, event: WatchEvent<Event>) -> anyhow::Result<()> {
        match event {
            WatchEvent::Added(event) => {
                if Self::is_recent_gcr_auth_failure(&event) {
                    debug!("{}", event.message.unwrap_or_else(|| "".into()));
                    let credentials = Credentials::from_gcloud(self.registry_url).await?;
                    let data = credentials.as_secret_bytes(self);
                    let pp = PostParams::default();
                    let secrets: Api<Secret> = Api::namespaced(self.client.clone(), self.namespace);
                    if secrets.get(self.secret_name).await.is_ok() {
                        secrets.replace(self.secret_name, &pp, data).await?;
                        debug!("Secret {} updated", self.secret_name);
                    } else {
                        secrets.create(&pp, data).await?;
                        debug!("Secret {} created", self.secret_name);
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Tests if the event is one for a recent auth failure.
    pub(crate) fn is_recent_gcr_auth_failure(event: &Event) -> bool {
        event // must be recent
            .last_timestamp
            .clone()
            .map(|time| Utc::now().signed_duration_since(time.0) < Duration::minutes(60))
            .unwrap_or(false)
            && event // source must be kubelet
                .source
                .clone()
                .map(|s| s.component)
                .unwrap_or(None)
                .map(|c| "kubelet" == c.as_str())
                .unwrap_or(false)
            && event // message must be a GCR auth failure
                .message
                .clone()
                .map(|m| Regex::new(Self::EVENT_MESSAGE_REGEX).unwrap().is_match(&m))
                .unwrap_or(false)
    }

    /// The Regex of the event messages corresponding to an auth failure against GCR.
    pub const EVENT_MESSAGE_REGEX: &'static str =
        r#"^Failed to pull image.*gcr\.io.*(?:(?:403 Forbidden)|(?:401 Unauthorized))$"#;
}
