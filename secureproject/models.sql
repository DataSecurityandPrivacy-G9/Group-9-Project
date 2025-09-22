-- users
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    pw_hash VARCHAR(128) NOT NULL,
    role VARCHAR(1) NOT NULL  -- 'H' or 'R'
);

-- patients
CREATE TABLE patients (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(80),
    last_name VARCHAR(80),
    gender_ct BYTEA NOT NULL,
    gender_nonce BYTEA NOT NULL,
    age_ct BYTEA NOT NULL,
    age_nonce BYTEA NOT NULL,
    weight DOUBLE PRECISION NOT NULL,
    height DOUBLE PRECISION NOT NULL,
    health_history TEXT NOT NULL,
    row_mac BYTEA NOT NULL,
    leaf_hash BYTEA NOT NULL
);

-- merkle nodes
CREATE TABLE merkle_nodes (
    node_id SERIAL PRIMARY KEY,
    level INT NOT NULL,
    index_in_level BIGINT NOT NULL,
    hash BYTEA NOT NULL
);
