package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "--version", "-v":
		fmt.Printf("cli-mimo25-go %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage:
  cli-mimo25-go encrypt -i <input-file> [-o <output-file>] [options]
  cli-mimo25-go decrypt -i <input-file> [-o <output-file>] [options]
  cli-mimo25-go --version

Options:
  -i, --input-file          Input file path (required)
  -o, --output-file         Output file path (optional, derived from input if not set)
      --password            Password for encryption/decryption (warns about security risks)
      --salt                Optional salt for key derivation
      --filename-encoding   Encoding for encrypted filenames: base32 (default) or base64

Examples:
  cli-mimo25-go encrypt -i test.txt
  cli-mimo25-go decrypt -i encrypted_file
  cli-mimo25-go encrypt -i test.txt -o encrypted.bin --password mypassword`)
}

type cliFlags struct {
	inputFile  string
	outputFile string
	password   string
	salt       string
	encoding   string
}

func parseFlags(args []string) (*cliFlags, error) {
	fs := flagSet("encrypt/decrypt")
	f := &cliFlags{}

	fs.StringVar(&f.inputFile, "i", "", "Input file path")
	fs.StringVar(&f.inputFile, "input-file", "", "Input file path")
	fs.StringVar(&f.outputFile, "o", "", "Output file path")
	fs.StringVar(&f.outputFile, "output-file", "", "Output file path")
	fs.StringVar(&f.password, "password", "", "Password")
	fs.StringVar(&f.salt, "salt", "", "Salt")
	fs.StringVar(&f.encoding, "filename-encoding", "base32", "Filename encoding")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if f.inputFile == "" {
		return nil, fmt.Errorf("input file is required (-i or --input-file)")
	}

	if _, err := os.Stat(f.inputFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("input file does not exist: %s", f.inputFile)
	}

	enc := strings.ToLower(f.encoding)
	if enc != "base32" && enc != "base64" {
		return nil, fmt.Errorf("unsupported filename encoding: %s (supported: base32, base64)", f.encoding)
	}
	f.encoding = enc

	return f, nil
}

func getPassword(flagPassword string) (string, error) {
	if flagPassword != "" {
		fmt.Fprintln(os.Stderr, "WARNING: Using --password on the command line is insecure.")
		fmt.Fprintln(os.Stderr, "Consider using an environment variable instead:")
		fmt.Fprintln(os.Stderr, "  set RCLONE_PASSWORD=yourpassword")
		fmt.Fprintln(os.Stderr, "Then omit --password and enter it when prompted.")
		fmt.Fprintln(os.Stderr, "Remember to clear your terminal history after using --password.")
		return flagPassword, nil
	}

	if envPass := os.Getenv("RCLONE_PASSWORD"); envPass != "" {
		return envPass, nil
	}

	fmt.Print("Enter password: ")
	defer fmt.Println()

	password, err := readPassword()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	return string(password), nil
}

func readPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	return bytes.TrimRight(password, "\r\n"), nil
}

func getSalt(flagSalt string) string {
	if flagSalt != "" {
		return flagSalt
	}

	fmt.Print("Enter salt (optional, press Enter to skip): ")
	reader := bufio.NewReader(os.Stdin)
	salt, _ := reader.ReadString('\n')
	return strings.TrimSpace(salt)
}

func deriveOutputPath(inputPath, encryptedName string) string {
	dir := filepath.Dir(inputPath)
	return filepath.Join(dir, encryptedName)
}

func runEncrypt(args []string) {
	flags, err := parseFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	password, err := getPassword(flags.password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	salt := getSalt(flags.salt)

	keys, err := DeriveKeys(password, salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving keys: %v\n", err)
		os.Exit(1)
	}

	outputPath := flags.outputFile
	if outputPath == "" {
		basename := filepath.Base(flags.inputFile)
		encryptedName, err := EncryptFilename(basename, keys, flags.encoding)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting filename: %v\n", err)
			os.Exit(1)
		}
		outputPath = deriveOutputPath(flags.inputFile, encryptedName)
	}

	if err := EncryptFile(flags.inputFile, outputPath, keys); err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted: %s -> %s\n", flags.inputFile, outputPath)
}

func runDecrypt(args []string) {
	flags, err := parseFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	password, err := getPassword(flags.password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	salt := getSalt(flags.salt)

	keys, err := DeriveKeys(password, salt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deriving keys: %v\n", err)
		os.Exit(1)
	}

	outputPath := flags.outputFile
	if outputPath == "" {
		basename := filepath.Base(flags.inputFile)
		decryptedName, err := DecryptFilename(basename, keys, flags.encoding)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting filename: %v\n", err)
			os.Exit(1)
		}
		outputPath = deriveOutputPath(flags.inputFile, decryptedName)
	}

	if err := DecryptFile(flags.inputFile, outputPath, keys); err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decrypted: %s -> %s\n", flags.inputFile, outputPath)
}
