-- +goose Up
CREATE TABLE IF NOT EXISTS Logs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    created_at TIMESTAMP NOT NULL,
    level TEXT NOT NULL,
    service TEXT NOT NULL,
    msg TEXT NOT NULL 
);

CREATE TABLE IF NOT EXISTS Users (
    id UUID PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    email TEXT NOT NULL,
    hashed_api_key TEXT NOT NULL,
    hashed_password TEXT NOT NULL DEFAULT 'unset',
    subscription BOOL NOT NULL DEFAULT 'basic'
);

CREATE INDEX idx_user_id ON Users (user_id);

-- +goose Down
DROP TABLE Logs;
DROP TABLE Users;