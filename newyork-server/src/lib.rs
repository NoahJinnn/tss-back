#![recursion_limit = "128"]
#[macro_use]
extern crate rocket;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

#[cfg(test)]
#[macro_use]
extern crate time_test;

pub mod auth;
pub mod routes;
pub mod server;
pub mod storage;
pub mod tests;
pub mod utils;

pub struct AppConfig {
    pub db: storage::db::DB,
    pub hcmc_api: String,
    pub alchemy_api: String,
}

pub type AnyhowError = rocket::response::Debug<anyhow::Error>;
