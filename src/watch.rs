use chrono::{Duration, Utc};
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::Event;
use kube::api::{ListParams, WatchEvent};
use kube::client::APIClient;
use kube::runtime::Informer;
use kube::Resource;
use regex::Regex;

use crate::common::KubeCrud;
use crate::{CredentialConfiguration, Credentials, Targets};

pub struct Watcher<'a> {
    client: APIClient,
    targets: Targets,
    secret_name: &'a str,
}

impl<'a> From<&'a Watcher<'a>> for CredentialConfiguration<'a> {
    fn from(w: &'a Watcher<'a>) -> Self {
        CredentialConfiguration::new(w.secret_name, &w.targets)
    }
}

impl Watcher<'_> {
    pub fn subcommand(name: &str) -> App {
        SubCommand::with_name(name)
            .about("Runs an out-of-cluster refresh service using your local 'gcloud' command")
            .arg(
                Arg::with_name("secret_name")
                    .value_name("SECRET NAME")
                    .help("The name of the dockerconfigjson secret to create/update")
                    .required(true)
                    .index(1),
            )
    }
    /// Main entry point for the watcher
    pub async fn run(
        client: APIClient,
        targets: Targets,
        matches: &ArgMatches<'_>,
    ) -> anyhow::Result<()> {
        let runner = Watcher {
            client,
            targets,
            secret_name: matches.value_of("secret_name").expect("SECRET NAME"),
        };
        debug!("Target secret: {}", runner.secret_name);
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
                    Credentials::from_gcloud()
                        .await?
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
