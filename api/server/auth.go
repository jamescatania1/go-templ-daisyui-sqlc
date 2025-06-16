package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/jamescatania1/go-templ-daisyui-sqlc/api/templates"
	"github.com/jamescatania1/go-templ-daisyui-sqlc/database"
	"github.com/jamescatania1/go-templ-daisyui-sqlc/database/sqlc"
)

const (
	accessTokenLifespan  time.Duration = 30 * time.Second
	refreshTokenLifespan time.Duration = 5 * time.Minute
	maxUserRefreshTokens int           = 10
)

type AccessToken struct {
	UserID    string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	jwt.RegisteredClaims
}

type RefreshToken struct {
	UserID  string `json:"id"`
	TokenID string `json:"token_id"`
	jwt.RegisteredClaims
}

var (
	ErrInvalidPassword = errors.New("password fails to meet requirements")
	ErrInvalidEmail    = errors.New("email fails to meet requirements")
)

func validEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.Join(ErrInvalidEmail, err)
	}
	return nil
}

func validPassword(password string) error {
	if len(password) < 8 || len(password) > 30 {
		return ErrInvalidPassword
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	if hasUpper && hasLower && hasDigit {
		return nil
	} else {
		return ErrInvalidPassword
	}
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPassword(password string, passwordHash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		return errors.Join(ErrInvalidPassword, err)
	}
	return nil
}

func createAccessToken(user *sqlc.User) (string, error) {
	accessToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&AccessToken{
			UserID:    user.ID.String(),
			Email:     user.Email,
			Name:      user.Name,
			CreatedAt: user.CreatedAt.Unix(),
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenLifespan)),
			},
		})
	return accessToken.SignedString(JWTSecret)
}

func createRefreshToken(user *sqlc.User) (string, uuid.UUID, error) {
	id := uuid.New()
	refreshToken := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		&RefreshToken{
			UserID:  user.ID.String(),
			TokenID: id.String(),
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenLifespan)),
			},
		})
	tokenString, err := refreshToken.SignedString(JWTSecret)
	return tokenString, id, err
}

func setTokenCookies(w http.ResponseWriter, accessToken string, refreshToken string) {
	if accessToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "access_token",
			Value:    accessToken,
			Path:     "/",
			Secure:   false,
			MaxAge:   int(accessTokenLifespan.Seconds()),
			HttpOnly: true,
		})
	}
	if refreshToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/",
			Secure:   false,
			MaxAge:   int(refreshTokenLifespan.Seconds()),
			HttpOnly: true,
		})
	}
}

func jwtKey(token *jwt.Token) (any, error) {
	return JWTSecret, nil
}

func Authenticate(next Handler) Handler {
	return Handler(func(w http.ResponseWriter, r *http.Request) (string, int, error) {
		accessTokenString := ""
		refreshTokenString := ""

		if accessTokenCookie, err := r.Cookie("access_token"); err == nil {
			accessTokenString = accessTokenCookie.Value
		}
		if refreshTokenCookie, err := r.Cookie("refresh_token"); err == nil {
			refreshTokenString = refreshTokenCookie.Value
		}

		if accessTokenString == "" && refreshTokenString == "" {
			return "Unauthorized", 401, errors.New("no access or refresh token found")
		}
		if accessTokenString != "" {
			accessToken := &AccessToken{}
			accessJWT, err := jwt.ParseWithClaims(accessTokenString, accessToken, jwtKey)
			if err == nil && accessJWT.Valid {
				userUUID, err := uuid.Parse(accessToken.UserID)
				if err != nil {
					return "Unauthorized", 401, err
				}
				user := &sqlc.User{
					ID:        userUUID,
					Email:     accessToken.Email,
					Name:      accessToken.Name,
					CreatedAt: time.Unix(accessToken.CreatedAt, 0).UTC(),
				}
				ctx := context.WithValue(r.Context(), "user", user)
				return next(w, r.WithContext(ctx))
			}
		}

		if refreshTokenString == "" {
			return "Unauthorized", 401, errors.New("missing refresh token")
		}

		refreshToken := &RefreshToken{}
		refreshJWT, err := jwt.ParseWithClaims(refreshTokenString, refreshToken, jwtKey)
		if err != nil || !refreshJWT.Valid {
			return "Unauthorized", 401, err
		}

		tx, err := database.Pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			panic(err)
		}
		defer tx.Rollback(r.Context())
		queries := database.Queries.WithTx(tx)

		if err := queries.DeleteExpiredRefreshTokens(r.Context(),
			sqlc.DeleteExpiredRefreshTokensParams{
				UserID:    uuid.MustParse(refreshToken.UserID),
				ExpiresAt: time.Now().UTC(),
			}); err != nil {
			panic(err)
		}

		res, err := queries.GetUserandRefreshToken(r.Context(), uuid.MustParse(refreshToken.UserID))
		if err != nil {
			tx.Commit(r.Context())
			if errors.Is(err, sql.ErrNoRows) {
				return "Unauthorized", 401, err
			} else {
				panic(err)
			}
		}
		user := res.User
		stored := res.RefreshToken
		if user.ID.String() != refreshToken.UserID ||
			stored.Token != refreshTokenString ||
			stored.ExpiresAt.Unix() < time.Now().Unix() ||
			int(res.TokenCount) >= maxUserRefreshTokens {
			tx.Commit(r.Context())
			return "Unauthorized", 401, errors.New("user refresh token is invalid, or there are too many tokens")
		}

		newAccessToken, err := createAccessToken(&user)
		if err != nil {
			tx.Commit(r.Context())
			panic(err)
		}
		newRefreshToken, refreshID, err := createRefreshToken(&user)
		if err != nil {
			tx.Commit(r.Context())
			panic(err)
		}

		if err := queries.InsertNewRefreshToken(r.Context(), sqlc.InsertNewRefreshTokenParams{
			ID:        refreshID,
			UserID:    user.ID,
			Token:     newRefreshToken,
			ExpiresAt: time.Now().Add(refreshTokenLifespan).UTC(),
		}); err != nil {
			panic(err)
		}

		if err := queries.DeleteRefreshToken(r.Context(), uuid.MustParse(refreshToken.TokenID)); err != nil {
			panic(err)
		}

		if err = tx.Commit(r.Context()); err != nil {
			panic(err)
		}

		setTokenCookies(w, newAccessToken, newRefreshToken)
		ctx := context.WithValue(r.Context(), "user", &user)
		return next(w, r.WithContext(ctx))
	})
}

func Login(w http.ResponseWriter, r *http.Request) (string, int, error) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		if err := validEmail(email); err != nil {
			return "Invalid email address", 400, err
		}
		if err := validPassword(password); err != nil {
			return "Invalid password provided", 400, err
		}

		tx, err := database.Pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			panic(err)
		}
		defer tx.Rollback(r.Context())
		queries := database.Queries.WithTx(tx)

		user, err := queries.GetUserByEmail(r.Context(), email)
		if err == sql.ErrNoRows {
			// dummy check to prevent a timing difference
			dummyHash := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZGHF7Y0Nf1XQ8nRpn0NPwG7qy6Y9e"
			bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
			return "Invalid email or password", 400, err
		} else if err != nil {
			panic(err)
		}

		if err := verifyPassword(password, user.PasswordHash); err != nil {
			return "Invalid email or password", 400, err
		}

		if err := queries.DeleteExpiredRefreshTokens(
			r.Context(),
			sqlc.DeleteExpiredRefreshTokensParams{
				UserID:    user.ID,
				ExpiresAt: time.Now().UTC(),
			}); err != nil {
			panic(err)
		}

		accessToken, err := createAccessToken(&user)
		if err != nil {
			panic(err)
		}
		refreshToken, refreshID, err := createRefreshToken(&user)
		if err != nil {
			panic(err)
		}

		if err := queries.InsertNewRefreshToken(r.Context(), sqlc.InsertNewRefreshTokenParams{
			ID:        refreshID,
			UserID:    user.ID,
			Token:     refreshToken,
			ExpiresAt: time.Now().Add(refreshTokenLifespan).UTC(),
		}); err != nil {
			panic(err)
		}

		if err = tx.Commit(r.Context()); err != nil {
			panic(err)
		}

		setTokenCookies(w, accessToken, refreshToken)
		GetFlashedMessage(w, r, "login") // clear previous error flash
		Flash(w, "login", "Login Successful")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", 200, nil
	}

	errorMessage, _ := GetFlashedMessage(w, r, "login")
	templates.Layout(templates.Login(errorMessage), "Sign In").Render(r.Context(), w)
	return "", 200, nil
}
func LoginError(w http.ResponseWriter, r *http.Request, message string, status int) {
	if message == "" {
		switch {
		case status == 401:
			message = "Unauthorized"
		default:
			message = "An unexpected error occurred"
		}
	}
	Flash(w, "login", message)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func Signup(w http.ResponseWriter, r *http.Request) (string, int, error) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")
		name := r.FormValue("name")

		if err := validEmail(email); err != nil {
			return "Invalid email address", 400, err
		}
		if err := validPassword(password); err != nil {
			return "Password does not meet requirements", 400, err
		}
		if len([]rune(name)) < 4 || len([]rune(name)) > 30 {
			return "Name must be between 4 and 30 characters", 400, errors.New("name does not meet requirements")
		}

		tx, err := database.Pool.BeginTx(r.Context(), pgx.TxOptions{})
		if err != nil {
			panic(err)
		}
		defer tx.Rollback(r.Context())
		queries := database.Queries.WithTx(tx)

		_, err = queries.GetUserByEmail(r.Context(), email)
		if err == nil {
			return "A user already exists with that email address", 400, errors.New("user already exists with requested email")
		} else if !errors.Is(err, sql.ErrNoRows) {
			panic(err)
		}

		passwordHash, err := hashPassword(password)
		if err != nil {
			panic(err)
		}

		user, err := queries.InsertNewUser(r.Context(), sqlc.InsertNewUserParams{
			Email:         email,
			Name:          name,
			PasswordHash:  passwordHash,
			EmailVerified: false,
		})
		if err != nil {
			panic(err)
		}

		verfication, err := queries.InsertNewEmailVerification(r.Context(), user.ID)
		if err != nil {
			panic(err)
		}

		if err := tx.Commit(r.Context()); err != nil {
			panic(err)
		}

		confirmURL := fmt.Sprintf("http://localhost:8000/confirm?user=%s&id=%s", verfication.UserID.String(), verfication.ID.String())
		SendEmail(email, confirmURL)

		GetFlashedMessage(w, r, "signup") // clear previous error flash
		Flash(w, "login", "Successfully created an account. You may now log in.")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return "", 200, nil
	}

	errorMessage, _ := GetFlashedMessage(w, r, "signup")
	templates.Layout(templates.Signup(errorMessage), "Create an Account").Render(r.Context(), w)
	return "", 200, nil
}
func SignupError(w http.ResponseWriter, r *http.Request, message string, status int) {
	log.Println("Reached error handler")
	if message == "" {
		switch {
		case status == 401:
			message = "Unauthorized"
		default:
			message = "An unexpected error occurred"
		}
	}
	Flash(w, "signup", message)
	http.Redirect(w, r, "/signup", http.StatusSeeOther)
}
