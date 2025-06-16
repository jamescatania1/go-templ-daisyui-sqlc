-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE user_id=$1 AND expires_at < $2;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens WHERE id = $1;

-- name: GetUserandRefreshToken :one
SELECT sqlc.embed(refresh_tokens), sqlc.embed(users),
    (SELECT COUNT(*) FROM refresh_tokens r WHERE r.user_id = $1) AS token_count
FROM users
JOIN refresh_tokens ON users.id = refresh_tokens.user_id
WHERE users.id = $1; 

-- name: InsertNewRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, token, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: InsertNewUser :one
INSERT INTO users (email, name, password_hash, email_verified)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: InsertNewEmailVerification :one
INSERT INTO email_verifications (user_id)
VALUES ($1)
RETURNING *;