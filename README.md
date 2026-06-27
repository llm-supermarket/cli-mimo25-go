# cli-mimo25-go

A small CLI tool that encrypts and decrypts files using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES-256-EME for the filenames.
- scrypt for key material.

## Installation

**Homebrew (macOS/Linux)**

```bash
brew tap llm-supermarket/cli-mimo25-go https://github.com/llm-supermarket/cli-mimo25-go
brew install cli-mimo25-go
```

**Scoop (Windows)**

```powershell
scoop bucket add cli-mimo25-go https://github.com/llm-supermarket/cli-mimo25-go
scoop install cli-mimo25-go
```

## Usage

```
cli-mimo25-go encrypt -i <input-file> [-o <output-file>] [options]
cli-mimo25-go decrypt -i <input-file> [-o <output-file>] [options]
cli-mimo25-go --version
```

### Options

| Flag | Description |
|------|-------------|
| `-i`, `--input-file` | Input file path (required) |
| `-o`, `--output-file` | Output file path (optional, derived from input filename if not set) |
| `--password` | Password for encryption/decryption (warns about security risks) |
| `--salt` | Optional salt for key derivation |
| `--filename-encoding` | Encoding for encrypted filenames: `base32` (default) or `base64` |

### Security

Using `--password` on the command line is insecure as it is visible in your shell history and process list. Instead, use an environment variable:

```bash
# Linux/macOS
export RCLONE_PASSWORD="yourpassword"

# Windows PowerShell
$env:RCLONE_PASSWORD = "yourpassword"
```

Then run the tool without `--password` and enter the password when prompted.

## Examples

### Encrypt a file

```bash
# Interactive password prompt, output filename is auto-encrypted (base32)
cli-mimo25-go encrypt -i test.txt

# With explicit output file
cli-mimo25-go encrypt -i test.txt -o encrypted.bin --password mypassword

# With a custom salt
cli-mimo25-go encrypt -i test.txt -o encrypted.bin --password mypassword --salt mysalt

# Using base64 filename encoding
cli-mimo25-go encrypt -i test.txt --filename-encoding base64
```

### Decrypt a file

```bash
# Interactive password prompt, output filename is auto-decrypted
cli-mimo25-go decrypt -i encrypted_file

# With explicit output file
cli-mimo25-go decrypt -i encrypted.bin -o decrypted.txt --password mypassword

# With a custom salt (must match the salt used during encryption)
cli-mimo25-go decrypt -i encrypted.bin -o decrypted.txt --password mypassword --salt mysalt

# Using base64 filename encoding
cli-mimo25-go decrypt -i encrypted_file --filename-encoding base64
```

### Using an environment variable

```bash
# Set password via environment variable
export RCLONE_PASSWORD="mysecret"

# The tool will use the env var automatically (no prompt)
cli-mimo25-go encrypt -i test.txt
cli-mimo25-go decrypt -i encrypted_file
```

## Encryption Details

This tool is **compatible with rclone's `crypt` backend** using the default settings:

- **Key derivation:** scrypt (N=16384, r=8, p=1), 80 bytes total
  - Bytes 0-31: Data key (NaCl SecretBox)
  - Bytes 32-63: Name key (AES-256-EME)
  - Bytes 64-79: Name tweak (EME tweak)
- **File contents:** NaCl SecretBox (XSalsa20 + Poly1305), 64 KiB blocks
- **Filenames:** AES-256-EME (ECB-Mix-ECB) with PKCS#7 padding
- **Filename encoding:** base32hex (RFC 4648, lowercase, no padding) by default, or base64 (URL-safe, no padding)
- **Salt:** A hardcoded default salt is used if none is provided

## Building from Source

Requires Go 1.25+.

```bash
git clone https://github.com/llm-supermarket/cli-mimo25-go
cd cli-mimo25-go
go build -o cli-mimo25-go .
```

### Running Tests

```bash
go test -v ./...
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest (`cli-mimo25-go.json`) and Homebrew formula (`Formula/cli-mimo25-go.rb`) in this repo.
