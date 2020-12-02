//! A high-level basic access authentication request guard for Rocket.rs

use base64;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;

/// Contains errors relating to the [BasicAuth] request guard
#[derive(Debug)]
pub enum BasicAuthError {
    /// Length check fail or misc error
    BadCount,
    /// Header is missing and is required
    Missing,
    /// Header is invalid in formatting/encoding
    Invalid,
}

/// Decodes a base64-encoded string into a tuple of `(name, password)` or a
/// [Option::None] if badly formatted, e.g. if an error occurs
fn decode_to_creds<T: Into<String>>(base64_encoded: T) -> Option<(String, String)> {
    let decoded_creds = match base64::decode(base64_encoded.into()) {
        Ok(vecu8_creds) => String::from_utf8(vecu8_creds).unwrap(),
        Err(_) => return None,
    };

    let split_vec: Vec<&str> = decoded_creds.split(":").collect();

    if split_vec.len() != 2 {
        None
    } else {
        Some((split_vec[0].to_string(), split_vec[1].to_string()))
    }
}

/// Authorisation header used as a request guard to securely get names and
/// passwords using [http basic
/// auth](https://en.wikipedia.org/wiki/Basic_access_authentication)
#[derive(Debug)]
pub struct BasicAuth {
    /// Required (user)name
    pub name: String,

    /// Required password
    pub password: String,
}

impl BasicAuth {
    /// Creates a new [BasicAuth] struct/request guard from given plaintext
    /// auth header or returns a [Option::None] if invalid
    pub fn new<T: Into<String>>(auth_header: T) -> Option<Self> {
        let key = auth_header.into();

        if key.len() < 7 || &key[..6] != "Basic " {
            return None;
        }

        let (name, password) = decode_to_creds(&key[6..])?;

        Some(Self { name, password })
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for BasicAuth {
    type Error = BasicAuthError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let keys: Vec<_> = request.headers().get("Authorization").collect();
        match keys.len() {
            0 => Outcome::Failure((Status::BadRequest, BasicAuthError::Missing)),
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
