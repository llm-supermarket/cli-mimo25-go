package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	fileMagic      = "RCLONE\x00\x00"
	fileMagicSize  = 8
	fileNonceSize  = 24
	fileHeaderSize = fileMagicSize + fileNonceSize

	blockHeaderSize = secretbox.Overhead // 16 bytes
	blockDataSize   = 64 * 1024         // 64KB
	blockSize       = blockHeaderSize + blockDataSize

	nameCipherBlockSize = 16 // AES block size
)

var fileMagicBytes = []byte(fileMagic)

var defaultSalt = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}

type FileNameEncoding string

const (
	EncodingBase32 FileNameEncoding = "base32"
	EncodingBase64 FileNameEncoding = "base64"
)

type Cipher struct {
	dataKey     [32]byte
	nameKey     [32]byte
	nameTweak   [nameCipherBlockSize]byte
	block       cipher.Block
	fileNameEnc fileNameEncoding
}

type fileNameEncoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

type caseInsensitiveBase32Encoding struct{}

func (caseInsensitiveBase32Encoding) EncodeToString(src []byte) string {
	encoded := base32.HexEncoding.EncodeToString(src)
	encoded = strings.TrimRight(encoded, "=")
	return strings.ToLower(encoded)
}

func (caseInsensitiveBase32Encoding) DecodeString(s string) ([]byte, error) {
	if strings.HasSuffix(s, "=") {
		return nil, errors.New("bad base32 filename encoding")
	}
	roundUpToMultipleOf8 := (len(s) + 7) &^ 7
	equals := roundUpToMultipleOf8 - len(s)
	s = strings.ToUpper(s) + "========"[:equals]
	return base32.HexEncoding.DecodeString(s)
}

func newFileNameEncoding(enc FileNameEncoding) (fileNameEncoding, error) {
	switch enc {
	case EncodingBase32:
		return caseInsensitiveBase32Encoding{}, nil
	case EncodingBase64:
		return base64.RawURLEncoding, nil
	default:
		return nil, errors.New("unknown filename encoding")
	}
}

func NewCipher(password, salt string, enc FileNameEncoding) (*Cipher, error) {
	fenc, err := newFileNameEncoding(enc)
	if err != nil {
		return nil, err
	}

	c := &Cipher{
		fileNameEnc: fenc,
	}

	const keySize = 32 + 32 + 16 // dataKey + nameKey + nameTweak
	var saltBytes []byte
	if salt != "" {
		saltBytes = []byte(salt)
	} else {
		saltBytes = defaultSalt
	}

	var key []byte
	if password == "" {
		key = make([]byte, keySize)
	} else {
		key, err = scrypt.Key([]byte(password), saltBytes, 16384, 8, 1, keySize)
		if err != nil {
			return nil, err
		}
	}

	copy(c.dataKey[:], key[:32])
	copy(c.nameKey[:], key[32:64])
	copy(c.nameTweak[:], key[64:80])

	c.block, err = aes.NewCipher(c.nameKey[:])
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Cipher) Encrypt(in io.Reader, out io.Writer) error {
	nonce := make([]byte, fileNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	if _, err := out.Write(fileMagicBytes); err != nil {
		return err
	}
	if _, err := out.Write(nonce); err != nil {
		return err
	}

	var nonceArray [fileNonceSize]byte
	copy(nonceArray[:], nonce)

	buf := make([]byte, blockDataSize)
	blockNum := 0

	for {
		n, readErr := io.ReadFull(in, buf)
		if n > 0 {
			currentNonce := nonceArray
			addNonce(&currentNonce, uint64(blockNum))

			encrypted := secretbox.Seal(nil, buf[:n], &currentNonce, &c.dataKey)
			if _, err := out.Write(encrypted); err != nil {
				return err
			}
			blockNum++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	return nil
}

func (c *Cipher) Decrypt(in io.Reader, out io.Writer) error {
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(in, header); err != nil {
		return errors.New("file is too short to be encrypted")
	}

	if !bytesEqual(header[:fileMagicSize], fileMagicBytes) {
		return errors.New("not an encrypted file - bad magic string")
	}

	var nonce [fileNonceSize]byte
	copy(nonce[:], header[fileMagicSize:])

	blockNum := 0
	buf := make([]byte, blockSize)

	for {
		n, readErr := io.ReadFull(in, buf)
		if n > 0 {
			currentNonce := nonce
			addNonce(&currentNonce, uint64(blockNum))

			decrypted, ok := secretbox.Open(nil, buf[:n], &currentNonce, &c.dataKey)
			if !ok {
				return errors.New("failed to authenticate decrypted block - bad password?")
			}
			if _, err := out.Write(decrypted); err != nil {
				return err
			}
			blockNum++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	return nil
}

// EncryptData encrypts data and returns the encrypted bytes.
func (c *Cipher) EncryptData(plaintext []byte) ([]byte, error) {
	var buf strings.Builder
	err := c.Encrypt(strings.NewReader(string(plaintext)), &buf)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

// DecryptData returns the decrypted data as a byte slice.
func (c *Cipher) DecryptData(encrypted []byte) ([]byte, error) {
	var buf strings.Builder
	err := c.Decrypt(strings.NewReader(string(encrypted)), &buf)
	if err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}

func (c *Cipher) EncryptFileName(in string) string {
	if in == "" {
		return ""
	}
	padded := pkcs7Pad(nameCipherBlockSize, []byte(in))
	ciphertext := emeEncrypt(c.block, c.nameTweak[:], padded)
	return c.fileNameEnc.EncodeToString(ciphertext)
}

func (c *Cipher) DecryptFileName(in string) (string, error) {
	if in == "" {
		return "", nil
	}
	rawCiphertext, err := c.fileNameEnc.DecodeString(in)
	if err != nil {
		return "", err
	}
	if len(rawCiphertext)%nameCipherBlockSize != 0 {
		return "", errors.New("not a multiple of blocksize")
	}
	if len(rawCiphertext) == 0 {
		return "", errors.New("too short after decode")
	}
	if len(rawCiphertext) > 2048 {
		return "", errors.New("too long after decode")
	}
	paddedPlaintext := emeDecryptBlock(c.block, c.nameTweak[:], rawCiphertext)
	plaintext, err := pkcs7Unpad(nameCipherBlockSize, paddedPlaintext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func IsEncrypted(data []byte) bool {
	if len(data) < fileMagicSize {
		return false
	}
	return bytesEqual(data[:fileMagicSize], fileMagicBytes)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func addNonce(n *[fileNonceSize]byte, x uint64) {
	carry := uint16(0)
	for i := range 8 {
		digit := n[i]
		xDigit := byte(x)
		x >>= 8
		carry += uint16(digit) + uint16(xDigit)
		n[i] = byte(carry)
		carry >>= 8
	}
	if carry != 0 {
		for i := 8; i < fileNonceSize; i++ {
			digit := n[i]
			newDigit := digit + 1
			n[i] = newDigit
			if newDigit >= digit {
				break
			}
		}
	}
}
