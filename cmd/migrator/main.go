package main

import (
	"errors"
	"flag"
	"fmt"
	"log"

	_ "github.com/glebarez/go-sqlite"
	"github.com/pressly/goose/v3"
)

func main() {
	var storagePath, migrationsPath string

	flag.StringVar(&storagePath, "storage-path", "", "path to SQLite storage")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to SQL migrations")
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

	if err := goose.Up(db, migrationsPath); err != nil {
		if errors.Is(err, goose.ErrAlreadyApplied) {
			fmt.Println("migrations already applied")

			return
		}
		panic(err)
	}

	log.Println("migrations applied successfully")
}
