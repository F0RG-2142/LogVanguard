-- name: NewLog :exec
INSERT INTO logs (id, user_id, created_at, level, service, msg)
VALUES (
    gen_random_uuid (),
    $1,
    NOW(),
    $2,
    $3,
    $4
);

-- name: GetAllLogs :many
SELECT * FROM logs WHERE user_id = $1 ORDER BY created_at ASC ;

-- name: GetLogsByDate :many
SELECT * FROM logs WHERE user_id = $1 AND created_at BETWEEN $1 AND $2;

-- name: GetLogsByLevel :many
SELECT * FROM logs WHERE user_id = $1 AND level = $2;

-- name: GetLogsByService :many
SELECT * FROM logs WHERE user_id = $1 AND service = $2;