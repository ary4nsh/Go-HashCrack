package libs

import (
    "bufio"
    "os"
)

func ReadHashes(path string) ([]string, error) {
    var hashes []string
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        hashes = append(hashes, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return hashes, nil
}

func ReadPasswords(path string) ([]string, error) {
    var passwords []string
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        passwords = append(passwords, scanner.Text())
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }
    return passwords, nil
}
