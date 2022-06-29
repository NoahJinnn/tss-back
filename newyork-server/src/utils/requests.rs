use anyhow::{anyhow, Result};
use reqwest::RequestBuilder;
use rocket::State;

use crate::{auth::guards::AuthPayload, AppConfig};

pub struct HttpClient {
    c: reqwest::Client,
    base_url: String,
}

impl HttpClient {
    pub fn new(base_url: String) -> HttpClient {
        HttpClient {
            c: reqwest::Client::new(),
            base_url,
        }
    }
}

pub async fn get(client: &HttpClient, path: &str) -> RequestBuilder {
    client.c.get(format!("{}{}", client.base_url, path))
}

pub async fn post(client: &HttpClient, path: &str) -> RequestBuilder {
    client.c.post(format!("{}{}", client.base_url, path))
}

pub async fn validate_auth_token(
    state: &State<AppConfig>,
    auth_payload: &AuthPayload,
) -> Result<()> {
    let http_client = HttpClient::new(state.hcmc_api.clone());

    let check_token_resp = get(&http_client, "/api/v1/storage/valid")
        .await
        .bearer_auth(&auth_payload.token)
        .send()
        .await?;

    if !check_token_resp.status().is_success() {
        return Err(anyhow!(
            "Failed to validate user's token {:#?}",
            check_token_resp.text().await?
        ));
    }

    Ok(())
}
