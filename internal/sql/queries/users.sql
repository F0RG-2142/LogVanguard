-- name: CreateUser :exec
INSERT INTO users (id, created_at, updated_at, email, hashed_api_key, hashed_password, subscription)
VALUES (
    gen_random_uuid (),
    NOW(),
    NOW(),
    $1,
    $2,
    $3,
    $4
);

-- name: GetUserByKey :one
SELECT id FROM users WHERE hashed_api_key = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: UpdateUser :exec
UPDATE users
SET
    updated_at = NOW(),
    email = $1,
    hashed_password= $2
WHERE
    id = $3;


-- name: UpdateSubscription :exec
UPDATE users
SET 
    has_notes_premium = 'true'
WHERE
    id = $1;