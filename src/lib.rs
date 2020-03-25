#[macro_use]
extern crate log;

pub mod credentials;
pub mod run;
pub mod setup;
pub mod watch;

pub type Credentials = credentials::Credentials;
pub type Watcher<'a> = watch::Watcher<'a>;
pub type Runner<'a> = run::Runner<'a>;
pub type Setup<'a> = setup::Setup<'a>;
