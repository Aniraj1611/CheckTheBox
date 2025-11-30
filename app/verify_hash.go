package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash := "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYUqRg7CfJW"
	password := "admin123"
	
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == nil {
		fmt.Println("✅ Hash MATCHES password 'admin123'")
	} else {
		fmt.Printf("❌ Hash does NOT match: %v\n", err)
	}
}
