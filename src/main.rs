extern crate k8s_openapi;
extern crate kube;
#[macro_use]
extern crate log;
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;
extern crate tokio;

use clap::{App, Arg};
use env_logger::Env;
use kube::client::APIClient;
use kube::config;

use k8s_gcr_auth_helper::{Runner, Setup, Targets, Watcher};

/// Entry point
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .args(&Targets::args())
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("Enable debug logging"),
        )
        .arg(
            Arg::with_name("in_cluster")
                .long("in-cluster")
                .help("Try to resolve in-cluster Kubernetes API connection details"),
        )
        .subcommand(Watcher::subcommand("gcloud"))
        .subcommand(Runner::subcommand("run"))
        .subcommand(Setup::remove_subcommand("remove"))
        .subcommand(Setup::add_subcommand("add"))
        .get_matches();
    // Set up logging
    {
        let default_level = if matches.is_present("debug") {
            format!("info,{}=debug", env!("CARGO_PKG_NAME").replace('-', "_"))
        } else {
            "info".into()
        };
        env_logger::Builder::from_env(Env::default().default_filter_or(&default_level)).init();
    }

    // Load the kubeconfig file.
    let kubeconfig = if matches.is_present("in_cluster") {
        config::incluster_config()?
    } else {
        config::load_kube_config().await?
    };

    let targets = Targets::from_matches(&matches, &kubeconfig.default_ns);
    debug!("Target registries: {}", targets.registry_urls().join(", "));
    debug!("Target namespace: {}", targets.namespace());

    // Create a new client
    let client = APIClient::new(kubeconfig.clone());

    if let Some(matches) = matches.subcommand_matches("local") {
        Watcher::run(client, targets, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("run") {
        Runner::run(client, targets, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("add") {
        Setup::add(client, targets, matches).await?;
    } else if let Some(matches) = matches.subcommand_matches("remove") {
        Setup::remove(client, targets, matches).await?;
    }
    Ok(())
}
