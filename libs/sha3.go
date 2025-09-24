package libs

import (
    "crypto/sha3"
    "fmt"
)

func CheckSHA3_224(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha3.Sum224([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA3-224): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA3-224 hash: %s\n", hash)
    }
}

func CheckSHA3_256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha3.Sum256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA3-256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA3-256 hash: %s\n", hash)
    }
}

func CheckSHA3_384(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha3.Sum384([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA3-384): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA3-384 hash: %s\n", hash)
    }
}

func CheckSHA3_512(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha3.Sum512([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA3-512): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA3-512 hash: %s\n", hash)
    }
}
