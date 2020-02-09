CREATE TYPE lifetime AS ENUM (
    'until-idle',
    'remember-me',
    'no-expiration'
);


CREATE TABLE identity (
    id integer NOT NULL,
    email text NOT NULL,
    password text NOT NULL
);

ALTER TABLE ONLY identity
    ADD CONSTRAINT identity_pkey PRIMARY KEY (id);

CREATE SEQUENCE identity_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE identity_id_seq OWNED BY identity.id;

ALTER TABLE ONLY identity ALTER COLUMN id SET DEFAULT nextval('identity_id_seq'::regclass);


CREATE TABLE token (
    id text NOT NULL,
    identity_id integer NOT NULL,
    secret text NOT NULL,
    lifetime text,
    created timestamp without time zone,
    last_active timestamp without time zone
);

ALTER TABLE ONLY token
    ADD CONSTRAINT token_pkey PRIMARY KEY (id);

ALTER TABLE ONLY token
    ADD CONSTRAINT token_identity_id_fkey FOREIGN KEY (identity_id) REFERENCES identity(id);

CREATE VIEW token_active AS
    SELECT token.id,
        token.identity_id,
        token.secret,
        token.lifetime,
        token.created,
        token.last_active
    FROM token
    WHERE (
        (token.lifetime = 'no-expiration'::text)
        OR (
            ((now() - '7 days'::interval) < token.created)
            AND (
                (token.lifetime = 'remember-me'::text)
                OR ((now() - '00:10:00'::interval) < token.last_active)
            )
        )
    );
