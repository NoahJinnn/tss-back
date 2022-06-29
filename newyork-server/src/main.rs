use log::info;
use server_lib::server;

#[rocket::main]
async fn main() {
    env_logger::init();
    info!("Server starting up");
    let _ = server::get_server().launch().await;
}
