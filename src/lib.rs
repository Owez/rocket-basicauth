//! [![Tests](https://github.com/Owez/rocket-basicauth/workflows/Tests/badge.svg)](https://github.com/Owez/rocket-basicauth/actions?query=workflow%3ATests) [![Docs](https://docs.rs/rocket-basicauth/badge.svg)](https://docs.rs/rocket-basicauth/)
//!
//! A high-level [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) request guard for [Rocket.rs](https://rocket.rs)
//!
//! ## Example
//!
//! ```rust
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
//! ## Installation
//!
//! Simply add the following to your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! rocket-basicauth = "2"
//! ```
//!
//! #### Disabling logging
//!
//! By default, this crate uses the [`log`](https://crates.io/crates/log) library to automatically add minimal trace-level logging, to disable this, instead write:
//!
//! ```toml
//! [dependencies]
//! rocket-basicauth = { version = "2", default-features = false }
//! ```
//!
//! #### Rocket 0.4
//!
//! Support for Rocket 0.4 is **decrepit** in the eyes of this crate but may still be used by changing the version, to do this, instead write:
//!
//! ```toml
//! [dependencies]
//! rocket-basicauth = "1"
//! ```
//!
//! ## Security
//!
//! Some essential security considerations to take into account are the following:
//!
//! - This crate has not been audited by any security professionals. If you are willing to do or have already done an audit on this crate, please create an issue as it would help out enormously! 😊
//! - This crate purposefully does not limit the maximum length of http basic auth headers arriving so please ensure your webserver configurations are set properly.

use base64;
#[cfg(feature = "log")]
use log::trace;
use rocket::http::Status;
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest, Request};

/// Contains errors relating to the [BasicAuth] request guard
#[derive(Debug)]
pub enum BasicAuthError {
    /// Length check fail or misc error
    BadCount,

    /// Header is missing and is required
    //Missing, // NOTE: removed migrating to 0.5 in v2 of this crate

    /// Header is invalid in formatting/encoding
    Invalid,
}

/// Decodes a base64-encoded string into a tuple of `(username, password)` or a
/// [Option::None] if badly formatted, e.g. if an error occurs
fn decode_to_creds<T: Into<String>>(base64_encoded: T) -> Option<(String, String)> {
    let decoded_creds = match base64::decode(base64_encoded.into()) {
        Ok(cred_bytes) => String::from_utf8(cred_bytes).unwrap(),
        Err(_) => return None,
    };

    if let Some((username, password)) = decoded_creds.split_once(":") {
        #[cfg(feature = "log")]
        {
            const TRUNCATE_LEN: usize = 64;
            let mut s = split_vec[0].to_string();
            let fmt_id = if split_vec[0].len() > TRUNCATE_LEN {
                s.truncate(TRUNCATE_LEN);
                format!("{}.. (truncated to {})", s, TRUNCATE_LEN)
            } else {
                split_vec[0].to_string()
            };

            trace!(
                "Decoded basic authentication credentials for user of id {}",
                fmt_id
            );
        }
      
        Some((username.to_owned(), password.to_owned()))
    } else {
        None
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
        #[cfg(feature = "log")]
        trace!("Basic authorization requested, starting decode process");

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
        // Tests: name:password
        assert_eq!(
            decode_to_creds("bmFtZTpwYXNzd29yZA=="),
            Some(("name".to_string(), "password".to_string()))
        );
        // Tests: name:pass:word
        assert_eq!(
            decode_to_creds("bmFtZTpwYXNzOndvcmQ="),
            Some(("name".to_string(), "pass:word".to_string()))
        );
        // Tests: emptypass:
        assert_eq!(
            decode_to_creds("ZW1wdHlwYXNzOg=="),
            Some(("emptypass".to_string(), "".to_string()))
        );
        // Tests: :
        assert_eq!(
            decode_to_creds("Og=="),
            Some(("".to_string(), "".to_string()))
        );
        assert_eq!(decode_to_creds("bm9jb2xvbg=="), None);
    }
}
