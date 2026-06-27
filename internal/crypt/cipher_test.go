package crypt

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testPassword = "Testpassword1"
const testSalt = "testsalt"
const testPlaintext = "## This is a test file\n\numbrella top kit charge tobacco know distance clinic detail prosper then gain museum ozone absurd neither rate correct certain scrub increase\n"

func TestEncryptDecryptRoundtrip(t *testing.T) {
	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	encrypted, err := c.EncryptData([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	if !IsEncrypted(encrypted) {
		t.Fatal("encrypted data does not start with rclone magic bytes")
	}

	decrypted, err := c.DecryptData(encrypted)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if string(decrypted) != testPlaintext {
		t.Errorf("roundtrip failed: got %q, want %q", string(decrypted), testPlaintext)
	}
}

func TestEncryptDecryptWithSalt(t *testing.T) {
	c, err := NewCipher(testPassword, testSalt, EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	encrypted, err := c.EncryptData([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	decrypted, err := c.DecryptData(encrypted)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if string(decrypted) != testPlaintext {
		t.Errorf("roundtrip with salt failed: got %q, want %q", string(decrypted), testPlaintext)
	}
}

func TestEncryptDecryptEmptyPassword(t *testing.T) {
	c, err := NewCipher("", "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	encrypted, err := c.EncryptData([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	decrypted, err := c.DecryptData(encrypted)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if string(decrypted) != testPlaintext {
		t.Errorf("roundtrip with empty password failed: got %q, want %q", string(decrypted), testPlaintext)
	}
}

func TestWrongPasswordFails(t *testing.T) {
	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	encrypted, err := c.EncryptData([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	wrong, err := NewCipher("wrongpassword", "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher with wrong password: %v", err)
	}

	_, err = wrong.DecryptData(encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong password")
	}
}

func TestWrongSaltFails(t *testing.T) {
	c, err := NewCipher(testPassword, testSalt, EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	encrypted, err := c.EncryptData([]byte(testPlaintext))
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	wrong, err := NewCipher(testPassword, "wrongsalt", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher with wrong salt: %v", err)
	}

	_, err = wrong.DecryptData(encrypted)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong salt")
	}
}

func TestDifferentSaltDifferentOutput(t *testing.T) {
	c1, _ := NewCipher(testPassword, "salt1", EncodingBase32)
	c2, _ := NewCipher(testPassword, "salt2", EncodingBase32)

	enc1, _ := c1.EncryptData([]byte(testPlaintext))
	enc2, _ := c2.EncryptData([]byte(testPlaintext))

	if bytes.Equal(enc1, enc2) {
		t.Error("different salts should produce different ciphertext")
	}
}

func TestFilenameEncryptDecryptBase32(t *testing.T) {
	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	filenames := []string{
		"TEST_FILE.txt",
		"hello.txt",
		"a.txt",
		"test/dir/file.txt",
		"file with spaces.txt",
		"file-with-dashes.txt",
		"file_with_underscores.txt",
		"12345.txt",
	}

	for _, fn := range filenames {
		encrypted := c.EncryptFileName(fn)
		if encrypted == fn {
			t.Errorf("encrypted filename should differ from original: %s", fn)
		}
		if encrypted == "" {
			t.Errorf("encrypted filename should not be empty: %s", fn)
		}

		decrypted, err := c.DecryptFileName(encrypted)
		if err != nil {
			t.Errorf("DecryptFileName(%q): %v", encrypted, err)
			continue
		}
		if decrypted != fn {
			t.Errorf("filename roundtrip: got %q, want %q", decrypted, fn)
		}
	}
}

func TestFilenameEncryptDecryptBase64(t *testing.T) {
	c, err := NewCipher(testPassword, "", EncodingBase64)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	filenames := []string{
		"TEST_FILE.txt",
		"hello.txt",
		"test/dir/file.txt",
	}

	for _, fn := range filenames {
		encrypted := c.EncryptFileName(fn)
		if encrypted == fn {
			t.Errorf("encrypted filename should differ from original: %s", fn)
		}

		decrypted, err := c.DecryptFileName(encrypted)
		if err != nil {
			t.Errorf("DecryptFileName(%q): %v", encrypted, err)
			continue
		}
		if decrypted != fn {
			t.Errorf("filename roundtrip: got %q, want %q", decrypted, fn)
		}
	}
}

func TestFilenameDifferentEncodingDifferentOutput(t *testing.T) {
	c32, _ := NewCipher(testPassword, "", EncodingBase32)
	c64, _ := NewCipher(testPassword, "", EncodingBase64)

	fn := "test.txt"
	enc32 := c32.EncryptFileName(fn)
	enc64 := c64.EncryptFileName(fn)

	if enc32 == enc64 {
		t.Error("different encodings should produce different encrypted filenames")
	}
}

func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{"rclone magic", []byte("RCLONE\x00\x00hello"), true},
		{"not rclone", []byte("hello world"), false},
		{"too short", []byte("RCL"), false},
		{"empty", []byte{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEncrypted(tt.data); got != tt.expected {
				t.Errorf("IsEncrypted() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecryptRcloneTestFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "kr9tu4e1da4u3nifdd99g9tf5o"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	decrypted, err := c.DecryptData(data)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	content := string(decrypted)
	if !strings.Contains(content, "umbrella top kit charge") {
		t.Errorf("unexpected content: %s", content)
	}
}

func TestDecryptRcloneBase64TestFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	decrypted, err := c.DecryptData(data)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	content := string(decrypted)
	if !strings.Contains(content, "umbrella top kit charge") {
		t.Errorf("unexpected content: %s", content)
	}
}

func TestEncryptDecryptToFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	outputPath := filepath.Join(dir, "output.bin")
	decryptPath := filepath.Join(dir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte(testPlaintext), 0644); err != nil {
		t.Fatal(err)
	}

	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Encrypt
	inData, _ := os.ReadFile(inputPath)
	encrypted, err := c.EncryptData(inData)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}
	if err := os.WriteFile(outputPath, encrypted, 0644); err != nil {
		t.Fatal(err)
	}

	// Decrypt
	outData, _ := os.ReadFile(outputPath)
	decrypted, err := c.DecryptData(outData)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}
	if err := os.WriteFile(decryptPath, decrypted, 0644); err != nil {
		t.Fatal(err)
	}

	result, _ := os.ReadFile(decryptPath)
	if string(result) != testPlaintext {
		t.Errorf("file roundtrip failed: got %q, want %q", string(result), testPlaintext)
	}
}

func TestLargeFileEncryptDecrypt(t *testing.T) {
	c, err := NewCipher(testPassword, "", EncodingBase32)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Create a file larger than one block (64KB)
	largeData := make([]byte, 100*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	encrypted, err := c.EncryptData(largeData)
	if err != nil {
		t.Fatalf("EncryptData: %v", err)
	}

	decrypted, err := c.DecryptData(encrypted)
	if err != nil {
		t.Fatalf("DecryptData: %v", err)
	}

	if !bytes.Equal(decrypted, largeData) {
		t.Error("large file roundtrip failed")
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	blockSize := 16
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"short", []byte("hello")},
		{"exact", make([]byte, 16)},
		{"multiple", make([]byte, 32)},
		{"long", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(blockSize, tt.data)
			if len(padded)%blockSize != 0 {
				t.Errorf("padded data not multiple of block size: %d", len(padded))
			}
			unpadded, err := pkcs7Unpad(blockSize, padded)
			if err != nil {
				t.Errorf("pkcs7Unpad: %v", err)
			}
			if !bytes.Equal(unpadded, tt.data) {
				t.Errorf("unpadded data doesn't match original")
			}
		})
	}
}
