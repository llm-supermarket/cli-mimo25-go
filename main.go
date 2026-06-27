package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/llm-supermarket-org/cli-mimo25-go/internal/crypt"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	args := os.Args[1:]

	var password string
	var salt string
	var saltFlag bool
	var input string
	var output string
	var encoding string
	var showVersion bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version", "-v":
			showVersion = true
		case "--password":
			if i+1 < len(args) {
				password = args[i+1]
				i++
				fmt.Fprintln(os.Stderr, "WARNING: Using --password is insecure. Use an environment variable instead:")
				fmt.Fprintln(os.Stderr, "  export RCLONE_PASSWORD=\"yourpassword\"")
				fmt.Fprintln(os.Stderr, "Then clear your terminal history with: history -d $HISTCMD")
			}
		case "-i", "--input-file":
			if i+1 < len(args) {
				input = args[i+1]
				i++
			}
		case "-o", "--output-file":
			if i+1 < len(args) {
				output = args[i+1]
				i++
			}
		case "-s", "--salt":
			saltFlag = true
			if i+1 < len(args) {
				salt = args[i+1]
				i++
			}
		case "-e", "--encoding":
			if i+1 < len(args) {
				encoding = args[i+1]
				i++
			}
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			os.Exit(1)
		}
	}

	if showVersion {
		fmt.Printf("rclone-encrypt-mimo25 %s\n", version)
		return
	}

	if input == "" {
		fmt.Fprintln(os.Stderr, "Error: input file is required (-i or --input-file)")
		fmt.Fprintln(os.Stderr, "Usage: rclone-encrypt-mimo25 -i <input> [-o <output>] [-e <encoding>] [-s <salt>]")
		os.Exit(1)
	}

	if encoding == "" {
		encoding = "base32"
	}

	// Read input file
	data, err := os.ReadFile(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
		os.Exit(1)
	}

	// Determine mode (encrypt or decrypt)
	isEncrypted := crypt.IsEncrypted(data)

	// Prompt for password if not provided via flag
	if password == "" {
		fmt.Print("Enter password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			// Fallback for environments without terminal
			reader := bufio.NewReader(os.Stdin)
			pwStr, _ := reader.ReadString('\n')
			password = strings.TrimRight(pwStr, "\r\n")
		} else {
			password = string(pw)
		}
	}

	// Prompt for salt if not provided via flag
	if !saltFlag {
		fmt.Print("Enter salt (optional, press Enter to skip): ")
		reader := bufio.NewReader(os.Stdin)
		saltStr, _ := reader.ReadString('\n')
		salt = strings.TrimRight(saltStr, "\r\n")
	}

	enc := crypt.FileNameEncoding(encoding)
	cipher, err := crypt.NewCipher(password, salt, enc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cipher: %v\n", err)
		os.Exit(1)
	}

	var result []byte
	if isEncrypted {
		result, err = decryptFile(cipher, data)
	} else {
		result, err = encryptFile(cipher, data)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Determine output file
	if output == "" {
		if isEncrypted {
			// For decryption, strip the extension
			output = strings.TrimSuffix(input, ".bin")
			if output == input {
				output = input + ".dec"
			}
		} else {
			output = input + ".bin"
		}
	}

	if err := os.WriteFile(output, result, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
		os.Exit(1)
	}

	if isEncrypted {
		fmt.Printf("Decrypted %s -> %s\n", input, output)
	} else {
		fmt.Printf("Encrypted %s -> %s\n", input, output)
	}
}

func encryptFile(cipher *crypt.Cipher, data []byte) ([]byte, error) {
	var buf strings.Builder
	err := cipher.Encrypt(strings.NewReader(string(data)), &buf)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func decryptFile(cipher *crypt.Cipher, data []byte) ([]byte, error) {
	var buf strings.Builder
	err := cipher.Decrypt(strings.NewReader(string(data)), &buf)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
