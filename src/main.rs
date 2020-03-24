extern crate k8s_openapi;
extern crate kube;
extern crate kube_derive;
#[macro_use]
extern crate log;
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;
extern crate tokio;

use clap::{App, Arg, SubCommand};
use env_logger::Env;
use kube::client::APIClient;
use kube::config;

use k8s_gcr_auth_helper::Watcher;

/// Entry point
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("registry_url")
                .short("r")
                .long("registry-url")
                .takes_value(true)
                .value_name("URL")
                .help("The registry to forward authentication for (default: https://gcr.io)"),
        )
        .arg(
            Arg::with_name("namespace")
                .short("n")
                .long("namespace")
                .takes_value(true)
                .value_name("NAMESPACE")
                .help("The namespace to create the secret in (defaults to current namespace)"),
        )
        .subcommand(
            SubCommand::with_name("watch")
                .about("Listens for authentication failures and creates/updates a secret")
                .arg(
                    Arg::with_name("secret_name")
                        .value_name("SECRET NAME")
                        .help("The name of the dockerconfigjson secret to create/update")
                        .required(true)
                        .index(0),
                ),
        )
        .get_matches();
    // Set up logging
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // What registry are we forwarding authentication to
    let registry_url = matches.value_of("registry_url").unwrap_or("https://gcr.io");

    // Load the kubeconfig file.
    let kubeconfig = config::load_kube_config().await?;

    // what namespace are we working in
    let namespace = matches
        .value_of("namespace")
        .unwrap_or(&kubeconfig.default_ns);

    // Create a new client
    let client = APIClient::new(kubeconfig.clone());

    if let Some(matches) = matches.subcommand_matches("watch") {
        Watcher::new(
            client.clone(),
            registry_url,
            namespace,
            matches.value_of("secret_name").expect("SECRET NAME"),
        )
        .run()
        .await?;
    }
    Ok(())
}
