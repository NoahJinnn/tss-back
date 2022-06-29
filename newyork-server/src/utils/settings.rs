#[derive(Deserialize, Debug)]
pub struct AppEnv {
    pub hcmc_host: String,
    pub alchemy_api: String,
}

#[derive(Deserialize, Debug)]
pub struct TestEnv {
    pub test_signin_url: String,
    pub test_email: String,
    pub test_pass: String,
}

pub fn get_app_env<T>(file_name: &str) -> T
where
    T: de::DeserializeOwned,
{
    dotenv::from_filename(file_name).unwrap_or_else(|_| panic!("Failed to read {}", file_name));
    match envy::from_env::<T>() {
        Ok(config) => config,
        Err(e) => panic!("Couldn't read app env config ({})", e),
    }
}

use serde::de;
