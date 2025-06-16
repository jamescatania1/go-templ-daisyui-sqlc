package server

import (
	"fmt"
	"net/http"
	"strings"
)

// Sets a 10-second cookie with the given [key] and value [message].
//
// Use GetFlashedMessage() to retrieve the message with the same key.
//
// To be used to save a message when redirecting from a POST request.
func Flash(w http.ResponseWriter, key string, message string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "flash_" + key,
		Value:    message,
		Path:     "/",
		MaxAge:   10,
		HttpOnly: true,
	})
}

// Retrieves a message cookie flashed in Flash() from the previous request.
//
// Clears the flashed message if it exists.
// Call opaquely to clear any previous flashed message.
//
// Returns empty string and [ErrNoCookie] if no flashed message was found.
func GetFlashedMessage(w http.ResponseWriter, r *http.Request, key string) (string, error) {
	cookie, err := r.Cookie("flash_" + key)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "flash_" + key,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	return cookie.Value, nil
}

func SendEmail(address string, message string) {
	if !IsProduction {
		fmt.Printf(
			"================ Email to %s ================\n%s\n%s",
			address, message, strings.Repeat("=", len(address)+43))
	} else {
		panic("email send not yet implemented")
	}
}
