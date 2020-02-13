#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate argon2;
extern crate rand;

use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest, Request};
use rocket::response::{self, content, Responder, Response};
use rocket::Outcome;
use rocket_contrib::databases::postgres;
use rocket_contrib::json::{Json, JsonValue};

#[database("db")]
struct DbConnection(postgres::Connection);

#[derive(Debug)]
struct JsonResponse {
    json: JsonValue,
    status: Status,
}

impl<'r> Responder<'r> for JsonResponse {
    fn respond_to(self, req: &Request) -> response::Result<'r> {
        Response::build_from(self.json.respond_to(&req).unwrap())
            .status(self.status)
            .header(ContentType::JSON)
            .ok()
    }
}

#[derive(Deserialize)]
struct TokenSpecification {
    email: String,
    password: String,
    lifetime: String,
}

#[post("/", format = "json", data = "<token_spec>")]
fn post_tokens(token_spec: Json<TokenSpecification>, db: DbConnection) -> JsonResponse {
    if token_spec.0.lifetime != "until-idle"
        && token_spec.0.lifetime != "remember-me"
        && token_spec.0.lifetime != "no-expiration"
    {
        return JsonResponse {
            json: json!({"error":"`lifetime` must be 'until-idle', 'remember-me', or 'no-expiration'"}),
            status: Status::BadRequest,
        };
    }

    // get user record for the e-mail
    let rows = db
        .query(
            "SELECT id, password FROM identity WHERE email = $1",
            &[&token_spec.0.email],
        )
        .unwrap();
    if rows.len() != 1 {
        return JsonResponse {
            json: json!({"error":"email not found or password invalid"}),
            status: Status::BadRequest,
        };
    }
    let user = rows.get(0);

    // verify the password
    let password_hash: String = user.get("password");
    let password = token_spec.0.password.as_bytes();
    let matches = argon2::verify_encoded(&password_hash, &password).unwrap();
    if !matches {
        return JsonResponse {
            json: json!({"error":"email not found or password invalid"}),
            status: Status::BadRequest,
        };
    }

    // create a token
    let user_id: i32 = user.get("id");
    let token_id = format!("{:0>32x}", rand::random::<u128>());
    let token_secret = format!(
        "{:0>32x}{:0>32x}",
        rand::random::<u128>(),
        rand::random::<u128>()
    );
    let rows = db
        .query(
            "INSERT INTO token VALUES ($1, $2, $3, $4, now(), now()) \
            RETURNING cast(extract(epoch from created) as integer) created, \
                      cast(extract(epoch from last_active) as integer) last_active",
            &[&token_id, &user_id, &token_secret, &token_spec.0.lifetime],
        )
        .unwrap();

    let token = rows.get(0);
    let created: i32 = token.get("created");
    let last_active: i32 = token.get("last_active");

    JsonResponse {
        json: json!({
            "id": token_id,
            "token_secret": token_secret,
            "lifetime": token_spec.0.lifetime,
            "created": created,
            "last_active": last_active
        }),
        status: Status::Ok,
    }
}

#[post("/", rank = 2)]
fn post_tokens_bad_content_type() -> JsonResponse {
    JsonResponse {
        json: json!({"error":"content-type must be application/json"}),
        status: Status::UnsupportedMediaType,
    }
}

#[derive(Serialize)]
struct Identity {
    id: i32,
    token_id: String,
}

#[derive(Debug)]
enum IdentityError {
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

#[get("/current")]
fn get_current_token(user: Identity, db: DbConnection) -> JsonResponse {
    query_token(user.token_id, user.id, db)
}

#[delete("/current")]
fn delete_current_token(user: Identity, db: DbConnection) -> JsonResponse {
    db.execute("DELETE FROM token WHERE id = $1", &[&user.token_id])
        .unwrap();
    JsonResponse {
        json: json!({"success":"the token used to make this request was deleted"}),
        status: Status::Ok,
    }
}

#[post("/current/refresh")]
fn post_refresh_current_token(user: Identity, db: DbConnection) -> JsonResponse {
    let rows = db
        .query(
            "UPDATE token SET last_active = now() WHERE id = $1 \
        RETURNING lifetime, cast(extract(epoch from created) as integer) created, \
        cast(extract(epoch from last_active) as integer) last_active",
            &[&user.token_id],
        )
        .unwrap();

    let token = rows.get(0);
    let lifetime: String = token.get("lifetime");
    let created: i32 = token.get("created");
    let last_active: i32 = token.get("last_active");

    JsonResponse {
        json: json!({
            "id": user.token_id,
            "lifetime": lifetime,
            "created": created,
            "last_active": last_active
        }),
        status: Status::Ok,
    }
}

#[get("/current/valid")]
fn get_current_token_valid(_user: Identity) {}

#[get("/<id>")]
fn get_token(id: String, user: Identity, db: DbConnection) -> JsonResponse {
    query_token(id, user.id, db)
}

#[delete("/<id>")]
fn delete_token(id: String, user: Identity, db: DbConnection) -> JsonResponse {
    if id == user.token_id {
        return JsonResponse {
            json: json!({"error": "to delete current token, use the /tokens/current endpoint"}),
            status: Status::BadRequest,
        };
    }

    let rows_deleted = db
        .execute(
            "DELETE FROM token_active WHERE id = $1 AND identity_id=$2",
            &[&id, &user.id],
        )
        .unwrap();

    if rows_deleted < 1 {
        return JsonResponse {
            json: json!({"error": "invalid or expired token id"}),
            status: Status::NotFound,
        };
    }

    JsonResponse {
        json: json!({"success": "the token was deleted"}),
        status: Status::Ok,
    }
}

#[get("/")]
fn get_tokens(user: Identity, db: DbConnection) -> JsonResponse {
    let rows = db
        .query(
            "SELECT id, lifetime, cast(extract(epoch from created) as integer) created, \
                cast(extract(epoch from last_active) as integer) last_active FROM token_active \
            WHERE identity_id = $1",
            &[&user.id],
        )
        .unwrap();

    let tokens: Vec<JsonValue> = rows.iter().map(
        |token| {
            let id: String = token.get("id");
            let lifetime: String = token.get("lifetime");
            let created: i32 = token.get("created");
            let last_active: i32 = token.get("last_active");
            json!({ "id": id, "lifetime": lifetime, "created": created, "last_active": last_active })
        }
    ).collect();

    JsonResponse {
        json: json!({"user_id": user.id, "tokens": tokens}),
        status: Status::Ok,
    }
}

#[derive(Deserialize)]
struct IdentitySpecification {
    email: String,
    password: String,
}

#[post("/", format = "json", data = "<user_spec>")]
fn post_users(
    user_spec: Json<IdentitySpecification>,
    db: DbConnection,
) -> Result<JsonResponse, postgres::error::Error> {
    // just length limit for "email", maybe some regex eventually
    if user_spec.email.len() > 150 {
        return Ok(JsonResponse {
            json: json!({"error": "`email` must be 150 characters or less"}),
            status: Status::BadRequest,
        });
    }

    // I have no idea if this is a good way to generate a salt
    let salt = rand::random::<u128>();

    let config = argon2::Config::default();
    let password_hash =
        argon2::hash_encoded(user_spec.password.as_bytes(), &salt.to_be_bytes(), &config).unwrap();

    let result = db.query(
        "INSERT INTO identity VALUES (default, $1, $2) RETURNING id",
        &[&user_spec.email, &password_hash],
    );

    match result {
        Ok(rows) => {
            let id: i32 = rows.get(0).get("id");

            Ok(JsonResponse {
                json: json!({"id": id, "email": user_spec.email}),
                status: Status::Ok,
            })
        }
        Err(e) => match e.as_db() {
            Some(db_error) => {
                if db_error.code == postgres::error::UNIQUE_VIOLATION {
                    return Ok(JsonResponse {
                        json: json!({"error": "`email` is already in use"}),
                        status: Status::BadRequest,
                    });
                };

                Err(e)
            }
            _ => Err(e),
        },
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

fn query_token(token_id: String, user_id: i32, db: DbConnection) -> JsonResponse {
    let rows = db
        .query(
            "SELECT lifetime, cast(extract(epoch from created) as integer) created, \
                cast(extract(epoch from last_active) as integer) last_active \
            FROM token_active WHERE id = $1 AND identity_id = $2",
            &[&token_id, &user_id],
        )
        .unwrap();
    if rows.len() != 1 {
        return JsonResponse {
            json: json!({"error": "invalid or expired token id"}),
            status: Status::NotFound,
        };
    }
    let other_token = rows.get(0);
    let lifetime: String = other_token.get("lifetime");
    let created: i32 = other_token.get("created");
    let last_active: i32 = other_token.get("last_active");

    JsonResponse {
        json: json!({
            "id": token_id,
            "user_id": user_id,
            "lifetime": lifetime,
            "created": created,
            "last_active": last_active
        }),
        status: Status::Ok,
    }
}

fn main() {
    rocket::ignite()
        .attach(DbConnection::fairing())
        .mount(
            "/tokens",
            routes![
                get_tokens,
                post_tokens,
                post_tokens_bad_content_type,
                get_current_token,
                delete_current_token,
                post_refresh_current_token,
                get_current_token_valid,
                get_token,
                delete_token
            ],
        )
        .mount("/users", routes![post_users])
        .register(catchers![
            bad_request,
            unauthorized,
            not_found,
            unprocessable_entity,
            internal_server_error
        ])
        .launch();
}
