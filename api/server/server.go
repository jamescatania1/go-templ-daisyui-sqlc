package server

import (
	"log"
	"net/http"
	"os"

	"github.com/a-h/templ"
	"github.com/jamescatania1/go-templ-daisyui-sqlc/api/templates"
	"github.com/jamescatania1/go-templ-daisyui-sqlc/database/sqlc"
)

var (
	IsProduction bool
	JWTSecret    []byte
)

func init() {
	IsProduction = os.Getenv("IS_PRODUCTION") == "true"
	JWTSecret = []byte(os.Getenv("JWT_SECRET"))
}

func Profile(w http.ResponseWriter, r *http.Request) (string, int, error) {
	user, _ := r.Context().Value("user").(*sqlc.User)
	templates.Layout(templates.Profile(user), user.Name).Render(r.Context(), w)
	return "", 200, nil
}
func ProfileError(w http.ResponseWriter, r *http.Request, message string, status int) {
	defaultErrorHandler(w, r, message, status)
}

func Run() error {
	static := http.FileServer(http.Dir("./public"))
	http.Handle("/static/", http.StripPrefix("/static/", static))

	http.Handle("/", templ.Handler(templates.Layout(templates.Index(), "Welcome!")))

	http.HandleFunc("/profile", ErrorHandle(Authenticate(Profile), ProfileError))

	http.HandleFunc("/login", ErrorHandle(Login, LoginError))
	http.HandleFunc("/signup", ErrorHandle(Signup, SignupError))

	log.Println("Listening on port 8001")

	return http.ListenAndServe("localhost:8001", nil)
}
