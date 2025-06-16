package database

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jamescatania1/go-templ-daisyui-sqlc/database/sqlc"
)

var Pool *pgxpool.Pool
var Queries *sqlc.Queries

func init() {
	pool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		log.Fatal(err)
	}
	log.Println("Successfully connected to database.")
	Pool = pool

	Queries = sqlc.New(Pool)
}
