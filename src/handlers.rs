use rocket_contrib::json::{Json, JsonValue};
use rocket::http::{ContentType, Status};
use rocket::request::Request;
use rocket::response::{self, Responder, Response};
use rocket_contrib::databases::postgres;

pub use crate::{DbConnection, Identity};

#[derive(Debug)]
pub struct JsonResponse {
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
pub struct TokenSpecification {
    email: String,
    password: String,
    lifetime: String,
}

#[post("/", format = "json", data = "<token_spec>")]
pub fn post_tokens(token_spec: Json<TokenSpecification>, db: DbConnection) -> JsonResponse {
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
pub fn post_tokens_bad_content_type() -> JsonResponse {
    JsonResponse {
        json: json!({"error":"content-type must be application/json"}),
        status: Status::UnsupportedMediaType,
    }
}

#[get("/current")]
pub fn get_current_token(user: Identity, db: DbConnection) -> JsonResponse {
    query_token(user.token_id, user.id, db)
}

#[delete("/current")]
pub fn delete_current_token(user: Identity, db: DbConnection) -> JsonResponse {
    db.execute("DELETE FROM token WHERE id = $1", &[&user.token_id])
        .unwrap();
    JsonResponse {
        json: json!({"success":"the token used to make this request was deleted"}),
        status: Status::Ok,
    }
}

#[post("/current/refresh")]
pub fn post_refresh_current_token(user: Identity, db: DbConnection) -> JsonResponse {
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
pub fn get_current_token_valid(_user: Identity) {}

#[get("/<id>")]
pub fn get_token(id: String, user: Identity, db: DbConnection) -> JsonResponse {
    query_token(id, user.id, db)
}

#[delete("/<id>")]
pub fn delete_token(id: String, user: Identity, db: DbConnection) -> JsonResponse {
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
pub fn get_tokens(user: Identity, db: DbConnection) -> JsonResponse {
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
pub struct IdentitySpecification {
    email: String,
    password: String,
}

#[post("/", format = "json", data = "<user_spec>")]
pub fn post_users(
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
