package libs

import (
    "crypto/sha1"
    "fmt"
)

func CheckSHA1(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha1.Sum([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA-1): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA-1 hash: %s\n", hash)
    }
}
