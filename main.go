package main

import (
    "fmt"
    "os"
    "sync"

    "Go-HashCrack/libs"
    "Go-HashCrack/libs/md2"

    "github.com/spf13/cobra"
)

type Flags struct {
    bcryptFlag	    bool
    md2Flag 	    bool
    md4Flag 	    bool
    md5Flag         bool
    sha1Flag        bool
    sha224Flag      bool
    sha256Flag      bool
    sha384Flag      bool
    sha512Flag      bool
    sha512_224Flag  bool
    sha512_256Flag  bool
    sha3_224Flag    bool
    sha3_256Flag    bool
    sha3_384Flag    bool
    sha3_512Flag    bool
    blake2b_256Flag bool
    blake2b_384Flag bool
    blake2b_512Flag bool
    blake2s_256Flag bool
    blake3_256Flag  bool
    blake3_512Flag  bool
    wordlistFile    string
    hashFile        string
}

func anyFlagSet(flags Flags) bool {
    return flags.bcryptFlag || 
        flags.md2Flag ||flags.md4Flag || flags.md5Flag || flags.sha1Flag || flags.sha224Flag ||
        flags.sha256Flag || flags.sha384Flag || flags.sha512Flag || flags.sha512_224Flag ||
        flags.sha512_256Flag || flags.sha3_224Flag || flags.sha3_256Flag || flags.sha3_384Flag ||
        flags.sha3_512Flag || flags.blake2b_256Flag || flags.blake2b_384Flag || 
        flags.blake2b_512Flag || flags.blake2s_256Flag || flags.blake3_256Flag || flags.blake3_512Flag
}

func main() {
    var flags Flags

    var rootCmd = &cobra.Command{
        Use:   "go-hashcrack [hash-file]",
        Short: "A multi-algorithm hash cracking tool",
        Long:  "Go-HashCrack is a powerful hash cracking tool that supports multiple hash algorithms",
        Run: func(cmd *cobra.Command, args []string) {
            // Check if no flags are set
            if !anyFlagSet(flags) {
                fmt.Println("Please provide at least one hash algorithm flag")
                return
            }

            // Check if wordlist file is provided
            if flags.wordlistFile == "" {
                fmt.Println("Please provide wordlist file (--wordlist string)")
                return
            }

            // Check if hash file argument is provided
            if len(args) == 0 {
                fmt.Println("Please provide a hash file as argument")
                return
            }

            flags.hashFile = args[0]

            // Read passwords and hashes
            passwords, err := libs.ReadPasswords(flags.wordlistFile)
            if err != nil {
                fmt.Printf("Error reading wordlist: %v\n", err)
                return
            }

            hashes, err := libs.ReadHashes(flags.hashFile)
            if err != nil {
                fmt.Printf("Error reading hash file: %v\n", err)
                return
            }

            var wg sync.WaitGroup
            functions := map[bool]func(){
                flags.bcryptFlag: func() {
		    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBcrypt(h, passwords)
                        }(hash)
                    }
                },
                flags.md2Flag: func() {
		    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            md2.CheckMD2(h, passwords)
                        }(hash)
                    }
                },
                flags.md4Flag: func() {
		    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckMD4(h, passwords)
                        }(hash)
                    }
                },
                flags.md5Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckMD5(h, passwords)
                        }(hash)
                    }
                },
                flags.sha1Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA1(h, passwords)
                        }(hash)
                    }
                },
                flags.sha224Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA224(h, passwords)
                        }(hash)
                    }
                },
                flags.sha256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA256(h, passwords)
                        }(hash)
                    }
                },
                flags.sha384Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA384(h, passwords)
                        }(hash)
                    }
                },
                flags.sha512Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA512(h, passwords)
                        }(hash)
                    }
                },
                flags.sha512_224Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA512_224(h, passwords)
                        }(hash)
                    }
                },
                flags.sha512_256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA512_256(h, passwords)
                        }(hash)
                    }
                },
                flags.sha3_224Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA3_224(h, passwords)
                        }(hash)
                    }
                },
                flags.sha3_256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA3_256(h, passwords)
                        }(hash)
                    }
                },
                flags.sha3_384Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA3_384(h, passwords)
                        }(hash)
                    }
                },
                flags.sha3_512Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckSHA3_512(h, passwords)
                        }(hash)
                    }
                },
                flags.blake2b_256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE2b_256(h, passwords)
                        }(hash)
                    }
                },
                flags.blake2b_384Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE2b_384(h, passwords)
                        }(hash)
                    }
                },
                flags.blake2b_512Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE2b_512(h, passwords)
                        }(hash)
                    }
                },
                flags.blake2s_256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE2s_256(h, passwords)
                        }(hash)
                    }
                },
                flags.blake3_256Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE3_256(h, passwords)
                        }(hash)
                    }
                },
                flags.blake3_512Flag: func() {
                    for _, hash := range hashes {
                        wg.Add(1)
                        go func(h string) {
                            defer wg.Done()
                            libs.CheckBLAKE3_512(h, passwords)
                        }(hash)
                    }
                },
            }

            for flag, function := range functions {
                if flag {
                    function()
                }
            }

            wg.Wait()
        },
    }

    // Allow flags to be specified anywhere in the command line
    rootCmd.Flags().SetInterspersed(true)

    // Hash algorithm flags
    rootCmd.Flags().BoolVarP(&flags.bcryptFlag, "bcrypt", "", false, "Crack bcrypt hashes")
    rootCmd.Flags().BoolVarP(&flags.md2Flag, "md2", "", false, "Crack MD2 hashes")
    rootCmd.Flags().BoolVarP(&flags.md4Flag, "md4", "", false, "Crack MD4 hashes")
    rootCmd.Flags().BoolVarP(&flags.md5Flag, "md5", "", false, "Crack MD5 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha1Flag, "sha1", "", false, "Crack SHA-1 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha224Flag, "sha224", "", false, "Crack SHA-224 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha256Flag, "sha256", "", false, "Crack SHA-256 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha384Flag, "sha384", "", false, "Crack SHA-384 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha512Flag, "sha512", "", false, "Crack SHA-512 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha512_224Flag, "sha512-224", "", false, "Crack SHA512/224 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha512_256Flag, "sha512-256", "", false, "Crack SHA512/256 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha3_224Flag, "sha3-224", "", false, "Crack SHA3-224 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha3_256Flag, "sha3-256", "", false, "Crack SHA3-256 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha3_384Flag, "sha3-384", "", false, "Crack SHA3-384 hashes")
    rootCmd.Flags().BoolVarP(&flags.sha3_512Flag, "sha3-512", "", false, "Crack SHA3-512 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake2b_256Flag, "blake2b-256", "", false, "Crack BLAKE2b-256 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake2b_384Flag, "blake2b-384", "", false, "Crack BLAKE2b-384 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake2b_512Flag, "blake2b-512", "", false, "Crack BLAKE2b-512 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake2s_256Flag, "blake2s-256", "", false, "Crack BLAKE2s-256 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake3_256Flag, "blake3-256", "", false, "Crack BLAKE3-256 hashes")
    rootCmd.Flags().BoolVarP(&flags.blake3_512Flag, "blake3-512", "", false, "Crack BLAKE3-512 hashes")

    // Required parameter flags
    rootCmd.Flags().StringVarP(&flags.wordlistFile, "wordlist", "", "", "Path to the wordlist file")

    if err := rootCmd.Execute(); err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
