package main

import (
	"log"

	"github.com/jamescatania1/go-templ-daisyui-sqlc/api/server"
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	log.Println("Initializing server...")

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
