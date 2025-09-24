package libs

import (
    "fmt"
    "lukechampine.com/blake3"
)

func CheckBLAKE3_256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake3.Sum256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE3-256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE3-256 hash: %s\n", hash)
    }
}

func CheckBLAKE3_512(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake3.Sum512([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE3-512): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE3-512 hash: %s\n", hash)
    }
}
