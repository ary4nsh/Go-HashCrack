package libs

import (
    "crypto/sha256"
    "crypto/sha512"
    "fmt"
)

func CheckSHA224(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha256.Sum224([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA-224): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA-224 hash: %s\n", hash)
    }
}

func CheckSHA256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA-256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA-256 hash: %s\n", hash)
    }
}

func CheckSHA384(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha512.Sum384([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA-384): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA-384 hash: %s\n", hash)
    }
}

func CheckSHA512(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha512.Sum512([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA-512): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA-512 hash: %s\n", hash)
    }
}

func CheckSHA512_224(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha512.Sum512_224([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA512/224): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA512/224 hash: %s\n", hash)
    }
}

func CheckSHA512_256(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", sha512.Sum512_256([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (SHA512/256): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for SHA512/256 hash: %s\n", hash)
    }
}
