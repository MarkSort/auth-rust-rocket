#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate argon2;
extern crate rand;

use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::response::content;
use rocket::Outcome;
use rocket_contrib::databases::postgres;

mod handlers;

#[database("db")]
pub struct DbConnection(postgres::Connection);


#[derive(Serialize)]
pub struct Identity {
    id: i32,
    token_id: String,
}

#[derive(Debug)]
pub enum IdentityError {
    TokenMissing,
    TokenInvalid,
}

impl<'a, 'r> FromRequest<'a, 'r> for Identity {
    type Error = IdentityError;

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {
        let cookies = request.cookies();
        let token = match cookies.get("token") {
            Some(x) => x.value(),
            None => return Outcome::Failure((Status::Unauthorized, IdentityError::TokenMissing)),
        };

        let db = request.guard::<DbConnection>().unwrap();
        let rows = db
            .query(
                "SELECT id, identity_id FROM token_active WHERE secret = $1",
                &[&token],
            )
            .unwrap();
        if rows.len() != 1 {
            return Outcome::Failure((Status::Unauthorized, IdentityError::TokenInvalid));
        }
        let token = rows.get(0);
        let user_id: i32 = token.get("identity_id");
        let token_id: String = token.get("id");

        Outcome::Success(Identity {
            id: user_id,
            token_id,
        })
    }
}

#[catch(400)]
fn bad_request() -> content::Json<&'static str> {
    content::Json("{\"error\":\"bad request\"}")
}

#[catch(401)]
fn unauthorized() -> content::Json<&'static str> {
    content::Json("{\"error\":\"unauthorized\"}")
}

#[catch(404)]
fn not_found() -> content::Json<&'static str> {
    content::Json("{\"error\":\"resource not found\"}")
}

#[catch(422)]
fn unprocessable_entity() -> content::Json<&'static str> {
    content::Json("{\"error\":\"unprocessable entity\"}")
}

#[catch(500)]
fn internal_server_error() -> content::Json<&'static str> {
    content::Json("{\"error\":\"internal server error\"}")
}

fn main() {
    rocket::ignite()
        .attach(DbConnection::fairing())
        .mount(
            "/tokens",
            routes![
                handlers::get_tokens,
                handlers::post_tokens,
                handlers::post_tokens_bad_content_type,
                handlers::get_current_token,
                handlers::delete_current_token,
                handlers::post_refresh_current_token,
                handlers::get_current_token_valid,
                handlers::get_token,
                handlers::delete_token
            ],
        )
        .mount("/users", routes![handlers::post_users])
        .register(catchers![
            bad_request,
            unauthorized,
            not_found,
            unprocessable_entity,
            internal_server_error
        ])
        .launch();
}
