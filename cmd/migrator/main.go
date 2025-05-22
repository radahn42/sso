package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

func main() {
	var storagePath, migrationsPath, migrationsTable string

	flag.StringVar(&storagePath, "storage-path", "", "path to SQLite storage")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to SQL migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "goose_db_version", "name of migrations table")
	flag.Parse()

	if storagePath == "" {
		log.Fatal("storage-path is required")
	}
	if migrationsPath == "" {
		log.Fatal("migrations-path is required")
	}

	db, err := goose.OpenDBWithDriver("sqlite", storagePath)
	if err != nil {
		panic("failed to open database")
	}
	defer db.Close()

	goose.SetTableName(migrationsTable)

	if err := goose.Up(db, migrationsPath); err != nil {
		if errors.Is(err, goose.ErrAlreadyApplied) {
			fmt.Println("migrations already applied")

			return
		}
		panic(err)
	}

	log.Println("migrations applied successfully")
}
