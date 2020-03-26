#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod common;
pub mod credentials;
mod oauth;
pub mod run;
pub mod setup;
pub mod watch;

pub type Targets = common::Targets;
pub type Credentials = credentials::Credentials;
pub type CredentialConfiguration<'a> = credentials::CredentialConfiguration<'a>;
pub type Watcher<'a> = watch::Watcher<'a>;
pub type Runner<'a> = run::Runner<'a>;
pub type Setup<'a> = setup::Setup<'a>;
