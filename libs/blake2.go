package libs

import (
    "fmt"
    "golang.org/x/crypto/blake2b"
    "golang.org/x/crypto/blake2s"
)

func CheckBLAKE2b_256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake2b.Sum256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE2b-256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE2b-256 hash: %s\n", hash)
    }
}

func CheckBLAKE2b_384(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake2b.Sum384([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE2b-384): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE2b-384 hash: %s\n", hash)
    }
}

func CheckBLAKE2b_512(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake2b.Sum512([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE2b-512): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE2b-512 hash: %s\n", hash)
    }
}

func CheckBLAKE2s_256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", blake2s.Sum256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (BLAKE2s-256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for BLAKE2s-256 hash: %s\n", hash)
    }
}
