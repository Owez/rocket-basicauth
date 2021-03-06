//! [![Tests](https://github.com/Owez/rocket-basicauth/workflows/Tests/badge.svg)](https://github.com/Owez/rocket-basicauth/actions?query=workflow%3ATests)
//! [![Docs](https://docs.rs/rocket-basicauth/badge.svg)](https://docs.rs/rocket-basicauth/)
//!
//! A high-level [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
//! request guard for [Rocket.rs](https://rocket.rs)
//!
//! # Example
//!
//! ```no_run
//! #[macro_use] extern crate rocket;
//!
//! use rocket_basicauth::BasicAuth;
//!
//! /// Hello route with `auth` request guard, containing a `name` and `password`
//! #[get("/hello/<age>")]
//! fn hello(auth: BasicAuth, age: u8) -> String {
//!     format!("Hello, {} year old named {}!", age, auth.username)
//! }
//!
//! #[launch]
//! fn rocket() -> _ {
//!     rocket::build().mount("/", routes![hello])
//! }
//! ```
//!
//! # Installation
//!
//! Simply add the following to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! rocket-basicauth = "2"
//! ```

use base64;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::outcome::Outcome;

/// Contains errors relating to the [BasicAuth] request guard
#[derive(Debug)]
pub enum BasicAuthError {
    /// Length check fail or misc error
    BadCount,

    /// Header is missing and is required
    //Missing,

    /// Header is invalid in formatting/encoding
    Invalid,
}

/// Decodes a base64-encoded string into a tuple of `(username, password)` or a
/// [Option::None] if badly formatted, e.g. if an error occurs
fn decode_to_creds<T: Into<String>>(base64_encoded: T) -> Option<(String, String)> {
    let decoded_creds = match base64::decode(base64_encoded.into()) {
        Ok(vecu8_creds) => String::from_utf8(vecu8_creds).unwrap(),
        Err(_) => return None,
    };

    let split_vec: Vec<&str> = decoded_creds.splitn(2, ":").collect();

    if split_vec.len() < 2 {
        None
    } else {
        Some((split_vec[0].to_string(), split_vec[1].to_string()))
    }
}

/// A high-level [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication)
/// request guard implementation, containing the `username` and `password` used for
/// authentication
///
/// # Example
///
/// ```no_run
/// #[macro_use] extern crate rocket;
///
/// use rocket_basicauth::BasicAuth;
///
/// /// Hello route with `auth` request guard, containing a `username` and `password`
/// #[get("/hello/<age>")]
/// fn hello(auth: BasicAuth, age: u8) -> String {
///     format!("Hello, {} year old named {}!", age, auth.username)
/// }
///
/// #[launch]
/// fn rocket() -> _ {
///     rocket::build().mount("/", routes![hello])
/// }
/// ```
#[derive(Debug)]
pub struct BasicAuth {
    /// Required username
    pub username: String,

    /// Required password
    pub password: String,
}

impl BasicAuth {
    /// Creates a new [BasicAuth] struct/request guard from a given plaintext
    /// http auth header or returns a [Option::None] if invalid
    pub fn new<T: Into<String>>(auth_header: T) -> Option<Self> {
        let key = auth_header.into();

        if key.len() < 7 || &key[..6] != "Basic " {
            return None;
        }

        let (username, password) = decode_to_creds(&key[6..])?;

        Some(Self { username, password })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BasicAuth {
    type Error = BasicAuthError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        match keys.len() {
            0 => Outcome::Forward(()),
            1 => match BasicAuth::new(keys[0]) {
                Some(auth_header) => Outcome::Success(auth_header),
                None => Outcome::Failure((Status::BadRequest, BasicAuthError::Invalid)),
            },
            _ => Outcome::Failure((Status::BadRequest, BasicAuthError::BadCount)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_to_creds_check() {
        assert_eq!(
            decode_to_creds("bmFtZTpwYXNzd29yZA=="),
            Some(("name".to_string(), "password".to_string()))
        );
        assert_eq!(
            decode_to_creds("ZW1wdHlwYXNzOg=="),
            Some(("emptypass".to_string(), "".to_string()))
        );
        assert_eq!(
            decode_to_creds("Og=="),
            Some(("".to_string(), "".to_string()))
        );
        assert_eq!(decode_to_creds("bm9jb2xvbg=="), None);
    }
}
