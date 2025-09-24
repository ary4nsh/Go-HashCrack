# Go-HashCrack
A high-performance, multi-threaded hash cracking tool written in Go that supports multiple cryptographic hash algorithms.

## Supported Hash Algorithms

- SHA-1: --sha1
- SHA-2 Family: --sha224, --sha256, --sha384, --sha512, --sha512-224, --sha512-256
- SHA-3 Family: --sha3-224, --sha3-256, --sha3-384, --sha3-512
- MD5: --md5
- BLAKE2: --blake2b-256, --blake2b-384, --blake2b-512, --blake2s-256
- BLAKE3: --blake3-256, --blake3-512

## Usage
```
  Go-HashCrack --[hash flag(s)] [hash file] --wordlist [path to your wordlist]

Flags:
      --blake2b-256       Crack BLAKE2b-256 hashes
      --blake2b-384       Crack BLAKE2b-384 hashes
      --blake2b-512       Crack BLAKE2b-512 hashes
      --blake2s-256       Crack BLAKE2s-256 hashes
      --blake3-256        Crack BLAKE3-256 hashes
      --blake3-512        Crack BLAKE3-512 hashes
  -h, --help              help for go-hashcrack
      --md5               Crack MD5 hashes
      --sha1              Crack SHA-1 hashes
      --sha224            Crack SHA-224 hashes
      --sha256            Crack SHA-256 hashes
      --sha3-224          Crack SHA3-224 hashes
      --sha3-256          Crack SHA3-256 hashes
      --sha3-384          Crack SHA3-384 hashes
      --sha3-512          Crack SHA3-512 hashes
      --sha384            Crack SHA-384 hashes
      --sha512            Crack SHA-512 hashes
      --sha512-224        Crack SHA512/224 hashes
      --sha512-256        Crack SHA512/256 hashes
  -w, --wordlist string   Path to the wordlist file
```

## Examples
Single Algorithm:
```
# Crack MD5 hashes
./Go-HashCrack --md5 md5_hashes.txt --wordlist rockyou.txt

# Crack SHA-256 hashes
./Go-HashCrack --sha256 sha256_hashes.txt -wordlist passwords.txt
```

Multiple Algorithms
```
# Crack multiple hash types simultaneously
./Go-HashCrack --md5 --sha1 --sha256 mixed_hashes.txt --wordlist wordlist.txt
```
