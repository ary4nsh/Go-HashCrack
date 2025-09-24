package libs

import (
    "crypto/md5"
    "fmt"
)

func CheckMD5(hash string, passwords []string) {
    found := false
    for _, password := range passwords {
        computedHash := fmt.Sprintf("%x", md5.Sum([]byte(password)))
        if computedHash == hash {
            fmt.Printf("[+] Password found (MD5): %s\n", password)
            found = true
        }
    }
    if !found {
        fmt.Printf("[-] No password found for MD5 hash: %s\n", hash)
    }
}
