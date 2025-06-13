package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// A simple tool to generate bcrypt hashes for user passwords.
// Usage: go run ./cmd/hasher "your-password-here"
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run ./cmd/hasher \"your-password-here\"")
	}
	password := os.Args[1]

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to hash password: %v", err)
	}

	fmt.Println(string(hashedPassword))
}
