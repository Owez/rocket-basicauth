# rocket-basicauth

[![Tests](https://github.com/Owez/rocket-basicauth/workflows/Tests/badge.svg)](https://github.com/Owez/rocket-basicauth/actions?query=workflow%3ATests)
[![Docs](https://docs.rs/rocket-basicauth/badge.svg)](https://docs.rs/rocket-basicauth/)

A high-level [basic access authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) request guard for [Rocket.rs](https://rocket.rs)

## Example

```rust
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

use rocket_basicauth::BasicAuth;

/// Hello route with `auth` request guard, containing a `name` and `password`
#[get("/hello/<age>")]
fn hello(auth: BasicAuth, age: u8) -> String {
    format!("Hello, {} year old named {}!", age, auth.name)
}

fn main() {
    rocket::ignite().mount("/", routes![hello]).launch();
}
```

## Installation

Simply add the following to your `Cargo.toml` file:

```toml
[dependencies]
rocket-basicauth = "1"
```
