// Copyright (c) Ultraviolet

package postgres

import (
	"fmt"
	"log"
	"os"
	"testing"

	pgclient "github.com/absmach/certs/internal/postgres"
	"github.com/ory/dockertest/v3"
	"github.com/jmoiron/sqlx"
)

var db *sqlx.DB

func TestMain(m *testing.M) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf(fmt.Sprintf("Could not connect to docker: %s", err))
	}

	cfg := []string{
		"POSTGRES_USER=test",
		"POSTGRES_PASSWORD=test",
		"POSTGRES_DB=test",
	}
	container, err := pool.Run("postgres", "13.3-alpine", cfg)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Could not start container: %s", err))
	}

	port := container.GetPort("5432/tcp")

	if err := pool.Retry(func() error {
		url := fmt.Sprintf("host=localhost port=%s user=test dbname=test password=test sslmode=disable", port)
		db, err = sqlx.Open("pgx", url)
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		log.Fatalf(fmt.Sprintf("Could not connect to docker: %s", err))
	}

	dbConfig := pgclient.Config{
		Host:        "localhost",
		Port:        port,
		User:        "test",
		Pass:        "test",
		Name:        "test",
		SSLMode:     "disable",
		SSLCert:     "",
		SSLKey:      "",
		SSLRootCert: "",
	}

	if db, err = pgclient.SetupWithConfig(*Migration(), dbConfig); err != nil {
		log.Fatalf(fmt.Sprintf("Could not setup test DB connection: %s", err))
	}

	code := m.Run()

	// Defers will not be run when using os.Exit
	db.Close()
	if err := pool.Purge(container); err != nil {
		log.Fatalf(fmt.Sprintf("Could not purge container: %s", err))
	}

	os.Exit(code)
}
