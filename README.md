# k8s-gcr-auth-helper

A Kubernetes authentication helper to expose per-user credentials as Image Pull Secrets for Google Container Registry

## Build

```
cargo install k8s-gcr-auth-helper
```                              

## Use

To install in the current namespace of your current Kubernetes cluster:

```
k8s-gcr-auth-helper add gcr-pull-secret-name
```                                                                    

To install and add to the default service account

```
k8s-gcr-auth-helper add --service-account default gcr-pull-secret-name
```                                                                    

*NOTE:* You can specify multiple `--service-account` arguments to install in multiple service accounts. To install in multiple namespaces run the command multiple times (with `--namespace` if you want to avoid changing namespace)

The first time the command is run it will open a browser to get an OAuth2 refresh token which will be stored in the cluster. 
A refresh service deployment will be created that listens for auth failures and refreshes the access token secret as required.

To remove use the same command with `add` replaced by `remove`, e.g.:

```
k8s-gcr-auth-helper remove gcr-pull-secret-name
```
