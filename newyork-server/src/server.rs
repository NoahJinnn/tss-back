use rocket;
use rocket::Request;
use rocksdb;

use crate::utils::settings::{get_app_env, AppEnv};

use super::routes::*;
use super::storage::db;
use super::AppConfig;

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

#[launch]
pub fn get_server() -> _ {
    let env_configs = get_app_env::<AppEnv>(".env.staging");
    let app_config = AppConfig {
        db: get_db(),
        hcmc_api: env_configs.hcmc_host,
        alchemy_api: env_configs.alchemy_api,
    };

    rocket::build()
        .register("/", catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                ping::ping,
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::chain_code_first_message,
                ecdsa::chain_code_second_message,
                ecdsa::sign_first,
                ecdsa::sign_second,
                ecdsa::rotate_first,
                ecdsa::rotate_second,
                ecdsa::recover,
                eth::tx_parameters,
                eth::tx_send,
            ],
        )
        .manage(app_config)
}

fn get_db() -> db::DB {
    match rocksdb::DB::open_default("./db") {
        Ok(db) => {
            info!("Init RocksDB connection successfully");
            db::DB::Local(db)
        }
        Err(e) => {
            error!("{:#?}", e);
            db::DB::ConnError(
                "Failed to connect RocksDB, please check your configuration".to_string(),
            )
        }
    }
}
