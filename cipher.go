package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rfjakob/eme"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	fileMagic      = "RCLONE\x00\x00"
	fileMagicSize  = 8
	fileNonceSize  = 24
	fileHeaderSize = fileMagicSize + fileNonceSize
	blockDataSize  = 64 * 1024
	keySize        = 80

	scryptN = 16384
	scryptR = 8
	scryptP = 1
)

var defaultSalt = []byte{
	0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
	0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
}

type Keys struct {
	DataKey   [32]byte
	NameKey   [32]byte
	NameTweak [16]byte
}

func DeriveKeys(password string, salt string) (*Keys, error) {
	saltBytes := []byte(salt)
	if len(saltBytes) == 0 {
		saltBytes = defaultSalt
	}

	key, err := scrypt.Key([]byte(password), saltBytes, scryptN, scryptR, scryptP, keySize)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	keys := &Keys{}
	copy(keys.DataKey[:], key[0:32])
	copy(keys.NameKey[:], key[32:64])
	copy(keys.NameTweak[:], key[64:80])

	return keys, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid PKCS#7 padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padding], nil
}

func encodeFilename(data []byte, encoding string) string {
	switch strings.ToLower(encoding) {
	case "base64":
		return base64.RawURLEncoding.EncodeToString(data)
	default:
		encoded := base32.HexEncoding.EncodeToString(data)
		encoded = strings.TrimRight(encoded, "=")
		return strings.ToLower(encoded)
	}
}

func decodeFilename(encoded string, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "base64":
		return base64.RawURLEncoding.DecodeString(encoded)
	default:
		roundUp := (len(encoded) + 7) &^ 7
		padding := roundUp - len(encoded)
		s := strings.ToUpper(encoded) + "========"[:padding]
		return base32.HexEncoding.DecodeString(s)
	}
}

func EncryptFilename(filename string, keys *Keys, encoding string) (string, error) {
	block, err := aes.NewCipher(keys.NameKey[:])
	if err != nil {
		return "", err
	}

	padded := pkcs7Pad([]byte(filename), aes.BlockSize)
	encrypted := eme.Transform(block, keys.NameTweak[:], padded, eme.DirectionEncrypt)

	return encodeFilename(encrypted, encoding), nil
}

func DecryptFilename(encoded string, keys *Keys, encoding string) (string, error) {
	encrypted, err := decodeFilename(encoded, encoding)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keys.NameKey[:])
	if err != nil {
		return "", err
	}

	decrypted := eme.Transform(block, keys.NameTweak[:], encrypted, eme.DirectionDecrypt)

	unpadded, err := pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}
	return string(unpadded), nil
}

func incrementNonce(nonce []byte) {
	for i := 0; i < len(nonce); i++ {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func EncryptFile(inputPath, outputPath string, keys *Keys) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	var nonce [fileNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte(fileMagic)); err != nil {
		return err
	}
	if _, err := outFile.Write(nonce[:]); err != nil {
		return err
	}

	for i := 0; i < len(inputData); i += blockDataSize {
		end := i + blockDataSize
		if end > len(inputData) {
			end = len(inputData)
		}
		chunk := inputData[i:end]

		encrypted := secretbox.Seal(nil, chunk, &nonce, &keys.DataKey)
		if _, err := outFile.Write(encrypted); err != nil {
			return err
		}

		incrementNonce(nonce[:])
	}

	return nil
}

func DecryptFile(inputPath, outputPath string, keys *Keys) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	if len(inputData) < fileHeaderSize {
		return fmt.Errorf("file too small to be an encrypted file")
	}

	if string(inputData[:fileMagicSize]) != fileMagic {
		return fmt.Errorf("invalid file magic (not an rclone-encrypted file)")
	}

	var nonce [fileNonceSize]byte
	copy(nonce[:], inputData[fileMagicSize:fileHeaderSize])

	outFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outFile.Close()

	offset := fileHeaderSize
	for offset < len(inputData) {
		end := offset + blockDataSize + secretbox.Overhead
		if end > len(inputData) {
			end = len(inputData)
		}
		block := inputData[offset:end]

		decrypted, ok := secretbox.Open(nil, block, &nonce, &keys.DataKey)
		if !ok {
			return fmt.Errorf("decryption failed (wrong password or corrupted file)")
		}

		if _, err := outFile.Write(decrypted); err != nil {
			return err
		}

		offset = end
		incrementNonce(nonce[:])
	}

	return nil
}
