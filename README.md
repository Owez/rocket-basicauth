# rocket-basicauth

[![Tests](https://github.com/Owez/rocket-basicauth/workflows/Tests/badge.svg)](https://github.com/Owez/rocket-basicauth/actions?query=workflow%3ATests) [![Docs](https://docs.rs/rocket-basicauth/badge.svg)](https://docs.rs/rocket-basicauth/)

A high-level [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) request guard for [Rocket.rs](https://rocket.rs)

## Example

```rust
#[macro_use] extern crate rocket;

use rocket_basicauth::BasicAuth;

/// Hello route with `auth` request guard, containing a `name` and `password`
#[get("/hello/<age>")]
fn hello(auth: BasicAuth, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, auth.username)
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![hello])
}
```

## Installation

Simply add the following to your `Cargo.toml` file:

```toml
[dependencies]
rocket-basicauth = "2"
```

#### Disabling logging

By default, this crate uses the [`log`](https://crates.io/crates/log) library to automatically add minimal trace-level logging, to disable this, instead write:

```toml
[dependencies]
rocket-basicauth = { version = "2", default-features = false }
```

#### Rocket 0.4

Support for Rocket 0.4 is **decrepit** in the eyes of this crate but may still be used by changing the version, to do this, instead write:

```toml
[dependencies]
rocket-basicauth = "1"
```

## Security

Some essential security considerations to take into account are the following:

- This crate has not been audited by any security professionals. If you are willing to do or have already done an audit on this crate, please create an issue as it would help out enormously! 😊
- This crate purposefully does not limit the maximum length of http basic auth headers arriving so please ensure your webserver configurations are set properly.
