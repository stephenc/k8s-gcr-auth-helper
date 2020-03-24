#[macro_use]
extern crate log;

pub mod credentials;
pub mod watch;

pub type Credentials = credentials::Credentials;
pub type Watcher<'a> = watch::Watcher<'a>;
