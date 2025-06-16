package server

import (
	"log"
	"net/http"

	"github.com/jamescatania1/go-templ-daisyui-sqlc/api/templates"
)

type Handler func(w http.ResponseWriter, r *http.Request) (string, int, error)
type ErrorHandler func(w http.ResponseWriter, r *http.Request, message string, status int)

const (
	ansiReset  = "\033[0m"
	ansiBlue   = "\033[34m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

func statusColor(status int) string {
	switch {
	case status >= 400:
		return ansiRed
	case status >= 300:
		return ansiYellow
	default:
		return ansiBlue
	}
}

func ErrorHandle(handler Handler, errorHandler ErrorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsProduction {
			defer func() {
				if rec := recover(); rec != nil {
					if errorHandler != nil {
						errorHandler(w, r, "An unexpected error occurred", 500)
					} else {
						defaultErrorHandler(w, r, "An unexpected error occurred", 500)
					}
				}
			}()
		}

		userMessage, status, err := handler(w, r)
		if err == nil && !IsProduction {
			log.Printf("%s<%s %s %d>%s", statusColor(status), r.Method, r.URL.Path, status, ansiReset)
			return
		}

		if errorHandler != nil {
			errorHandler(w, r, userMessage, status)
		} else {
			defaultErrorHandler(w, r, userMessage, status)
		}

		if !IsProduction {
			if status < 500 {
				log.Printf("%s<%s %s %d>%s %v", statusColor(status), r.Method, r.URL.Path, status, ansiReset, err)
			} else {
				panic(err)
			}
		}
	}
}
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, message string, status int) {
	w.WriteHeader(status)
	templates.Layout(templates.Error(message), "Error").Render(r.Context(), w)
}
