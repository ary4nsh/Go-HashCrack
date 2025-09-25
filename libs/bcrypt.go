package libs

import (
	"golang.org/x/crypto/bcrypt"
	"fmt"
)

func CheckBcrypt(hash string, passwords []string) {
	found := false
	for _, password := range passwords {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err == nil {
			fmt.Printf("[+] Password found (Bcrypt): %s\n", password)
			found = true
		}
	}
	if !found {
		fmt.Printf("[-] No password found for Bcrypt hash: %s\n", hash)
	}
}
