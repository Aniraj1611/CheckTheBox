package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash := "$2a$10$lVHYpvwuErgEg8lE9LMLYOBLOjR5ZGRIpz0vDZqofxDYziURLDEWK"
	
	passwords := []string{
		"password",
		"password123",
		"admin",
		"admin123",
		"checkthebox",
		"test123",
		"Password1!",
	}
	
	for _, pw := range passwords {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
		if err == nil {
			fmt.Printf("✅ MATCH: Password is '%s'\n", pw)
			return
		}
	}
	fmt.Println("❌ No match found in common passwords")
}
