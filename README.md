# rclone-encrypt-mimo25

A small CLI tool that encrypts and decrypts files using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default.

A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for key material.

## Installation

**Homebrew (macOS/Linux)**

```bash
brew tap llm-supermarket-org/cli-mimo25-go https://github.com/llm-supermarket-org/cli-mimo25-go
brew install rclone-encrypt-mimo25
```

**Scoop (Windows)**

```powershell
scoop bucket add rclone-encrypt-mimo25 https://github.com/llm-supermarket-org/cli-mimo25-go
scoop install rclone-encrypt-mimo25
```

## Usage

### Encrypt a file

```bash
# Encrypt with interactive password prompt
rclone-encrypt-mimo25 -i secret.txt

# Encrypt with --password flag (insecure - use env var instead)
rclone-encrypt-mimo25 --password "MyPassword" -i secret.txt -o secret.txt.bin

# Encrypt with a salt
rclone-encrypt-mimo25 --password "MyPassword" -s "my-salt" -i secret.txt

# Encrypt with base64 filename encoding
rclone-encrypt-mimo25 -e base64 -i secret.txt
```

### Decrypt a file

```bash
# Decrypt with interactive password prompt
rclone-encrypt-mimo25 -i secret.txt.bin

# Decrypt with --password flag
rclone-encrypt-mimo25 --password "MyPassword" -i secret.txt.bin -o secret.txt

# Decrypt with a salt (must match the salt used during encryption)
rclone-encrypt-mimo25 --password "MyPassword" -s "my-salt" -i secret.txt.bin
```

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--password` | | Password for encryption/decryption (insecure, prefer env var) |
| `-s`, `--salt` | | Optional salt for key derivation |
| `-e`, `--encoding` | | Filename encoding: `base32` (default) or `base64` |
| `-i`, `--input-file` | | **Required.** Input file path |
| `-o`, `--output-file` | | Output file path (optional, auto-detected) |
| `--version` | `-v` | Print version and exit |

### Security Warning

Using `--password` on the command line is insecure as the password will be visible in your shell history and process list. Instead, use an environment variable:

```bash
# Set the password as an environment variable
export RCLONE_PASSWORD="your-secure-password"
rclone-encrypt-mimo25 -i secret.txt

# Clear your shell history entry after setting the variable
history -d $HISTCMD
```

On Windows (PowerShell):

```powershell
$env:RCLONE_PASSWORD = "your-secure-password"
rclone-encrypt-mimo25 -i secret.txt
```

## How it works

This tool is compatible with [rclone's crypt backend](https://rclone.org/crypt/). Files encrypted with this tool can be decrypted by rclone and vice versa, as long as the same password, salt, and filename encoding settings are used.

The encrypted file format is:
- 8-byte magic header: `RCLONE\x00\x00`
- 24-byte random nonce
- Encrypted data blocks (64KB each, NaCl SecretBox)

Filenames are encrypted using EME (ECB-Mix-ECB) wide-block encryption with AES.

## Building from Source

Requires Go 1.25+.

```bash
git clone https://github.com/llm-supermarket-org/cli-mimo25-go
cd cli-mimo25-go
go build -o rclone-encrypt-mimo25 .
```

### Running tests

```bash
go test ./...
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux and macOS (amd64/arm64) and Windows (amd64), publishes a GitHub Release, and updates the Scoop manifest (`rclone-encrypt-mimo25.json`) and Homebrew formula (`Formula/rclone-encrypt-mimo25.rb`) in this repo.
