use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthPayload {
    pub token: String,
    pub user_id: String,
}
const TOKEN_TYPE: &str = "Bearer";

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthPayload {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let authorization_header: &str = match request.headers().get_one("Authorization") {
            Some(header) => header,
            None => return Outcome::Failure((Status::Unauthorized, ())),
        };

        let mut header_parts = authorization_header.split_whitespace();
        let token_type = header_parts.next();

        if let Some(tk_type) = token_type {
            if !tk_type.eq(TOKEN_TYPE) {
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        }

        let token = header_parts.next().unwrap_or("");
        let user_id: &str = request.headers().get_one("user_id").unwrap_or("");

        debug!("Auth token - user id: {} - {}", token, user_id);

        if token.is_empty() || user_id.is_empty() {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        Outcome::Success(AuthPayload {
            token: token.to_owned(),
            user_id: user_id.to_owned(),
        })
    }
}
