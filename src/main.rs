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

use k8s_gcr_auth_helper::{Runner, Setup, Watcher};

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
        .arg(
            Arg::with_name("debug")
                .short("d")
                .long("debug")
                .help("Enable debug logging"),
        )
        .arg(
            Arg::with_name("in_cluster")
                .long("in-cluster")
                .help("Try to resolve in-cluster Kubernetes API connection details")
        )
        .subcommand(
            SubCommand::with_name("local")
                .about("Locally listens for authentication failures and creates/updates a secret using gcloud")
                .arg(
                    Arg::with_name("secret_name")
                        .value_name("SECRET NAME")
                        .help("The name of the dockerconfigjson secret to create/update")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("run")
                .about("Controller for in-cluster listening for authentication failures and creates/updates a secret using a refresh token secret created by 'add'")
                .arg(
                    Arg::with_name("secret_name")
                        .value_name("SECRET NAME")
                        .help("The name of the dockerconfigjson secret to create/update")
                        .required(true)
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("remove")
                .about("Removes an in-cluster controller")
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
                        .takes_value(true)
                        .help("The service account to update the imagePullSecrets of (default: default)")
                )
        )
        .subcommand(
            SubCommand::with_name("add")
                .about("Adds an in-cluster controller")
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
                        .long("force-auth")
                        .help("Force renewal of the refresh token even if already configured"),
                )
                .arg(
                    Arg::with_name("scope")
                        .long("scope")
                        .value_name("SCOPE")
                        .takes_value(true)
                        .help("The token scope to request (default: https://www.googleapis.com/auth/cloud-platform)")
                )
                .arg(
                    Arg::with_name("service_account")
                        .long("service-account")
                        .value_name("NAME")
                        .takes_value(true)
                        .help("The service account to update the imagePullSecrets of (default: default)")
                )
                .arg(
                    Arg::with_name("controller_image")
                        .long("controller-image")
                        .value_name("IMAGE")
                        .takes_value(true)
                        .help(&format!("The controller image to use (default: {})", Setup::default_controller_image()))
                )
            ,
        )
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

    // What registry are we forwarding authentication to
    let registry_url = matches.value_of("registry_url").unwrap_or("https://gcr.io");
    debug!("Target registry: {}", registry_url);

    // Load the kubeconfig file.
    let kubeconfig = if matches.is_present("in_cluster") {
        config::incluster_config()?
    } else {
        config::load_kube_config().await?
    };

    // what namespace are we working in
    let namespace = matches
        .value_of("namespace")
        .unwrap_or(&kubeconfig.default_ns);
    debug!("Target namespace: {}", namespace);

    // Create a new client
    let client = APIClient::new(kubeconfig.clone());

    if let Some(matches) = matches.subcommand_matches("local") {
        Watcher::run(
            client.clone(),
            registry_url,
            namespace,
            matches.value_of("secret_name").expect("SECRET NAME"),
        )
        .await?;
    } else if let Some(matches) = matches.subcommand_matches("run") {
        Runner::run(
            client.clone(),
            registry_url,
            namespace,
            matches.value_of("secret_name").expect("SECRET NAME"),
        )
        .await?;
    } else if let Some(matches) = matches.subcommand_matches("add") {
        Setup::add(
            client.clone(),
            registry_url,
            namespace,
            matches.value_of("secret_name").expect("SECRET NAME"),
            matches.is_present("no_browser"),
            matches.is_present("force_auth"),
            matches.value_of("scope"),
            matches.value_of("controller_image"),
            matches.value_of("service_account"),
        )
        .await?;
    } else if let Some(matches) = matches.subcommand_matches("remove") {
        Setup::remove(
            client.clone(),
            registry_url,
            namespace,
            matches.value_of("secret_name").expect("SECRET NAME"),
            matches.value_of("service_account"),
        )
        .await?;
    }
    Ok(())
}
