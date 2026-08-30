// Command migrate applies goose SQL migrations against the configured database.
//
// Usage: migrate [up|down|status|version]
package main

import (
	"context"
	"database/sql"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/benlik386/asm/internal/config"
	"github.com/benlik386/asm/migrations"
)

func main() {
	cfg := config.LoadAPI()

	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("dialect: %v", err)
	}

	if err := goose.RunContext(context.Background(), cmd, db, "."); err != nil {
		log.Fatalf("goose %s: %v", cmd, err)
	}
	log.Printf("migrate %s: ok", cmd)
}
