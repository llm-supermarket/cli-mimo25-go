package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveKeysDeterministic(t *testing.T) {
	keys1, err := DeriveKeys("testpassword", "")
	if err != nil {
		t.Fatal(err)
	}
	keys2, err := DeriveKeys("testpassword", "")
	if err != nil {
		t.Fatal(err)
	}
	if keys1.DataKey != keys2.DataKey {
		t.Error("DataKey not deterministic")
	}
	if keys1.NameKey != keys2.NameKey {
		t.Error("NameKey not deterministic")
	}
	if keys1.NameTweak != keys2.NameTweak {
		t.Error("NameTweak not deterministic")
	}
}

func TestDeriveKeysWithSalt(t *testing.T) {
	keys1, _ := DeriveKeys("testpassword", "salt1")
	keys2, _ := DeriveKeys("testpassword", "salt2")
	if keys1.DataKey == keys2.DataKey {
		t.Error("Different salts should produce different keys")
	}
}

func TestDeriveKeysDifferentPasswords(t *testing.T) {
	keys1, _ := DeriveKeys("password1", "")
	keys2, _ := DeriveKeys("password2", "")
	if keys1.DataKey == keys2.DataKey {
		t.Error("Different passwords should produce different keys")
	}
}

func TestPKCS7PadUnpad(t *testing.T) {
	data := []byte("hello")
	padded := pkcs7Pad(data, 16)
	if len(padded)%16 != 0 {
		t.Error("Padded data not multiple of block size")
	}
	unpadded, err := pkcs7Unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
	if string(unpadded) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(unpadded))
	}
}

func TestPKCS7PadFullBlock(t *testing.T) {
	data := make([]byte, 16)
	for i := range data {
		data[i] = byte(i)
	}
	padded := pkcs7Pad(data, 16)
	if len(padded) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(padded))
	}
	unpadded, err := pkcs7Unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpadded) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(unpadded))
	}
}

func TestPKCS7UnpadEmpty(t *testing.T) {
	_, err := pkcs7Unpad([]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestPKCS7UnpadInvalid(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x00}
	_, err := pkcs7Unpad(data)
	if err == nil {
		t.Error("Expected error for invalid padding")
	}
}

func TestEncodeDecodeFilenameBase32(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encoded := encodeFilename(data, "base32")
	decoded, err := decodeFilename(encoded, "base32")
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(data) {
		t.Errorf("Length mismatch: %d vs %d", len(decoded), len(data))
	}
	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("Byte %d mismatch: %d vs %d", i, decoded[i], data[i])
		}
	}
}

func TestEncodeDecodeFilenameBase64(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	encoded := encodeFilename(data, "base64")
	decoded, err := decodeFilename(encoded, "base64")
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(data) {
		t.Errorf("Length mismatch: %d vs %d", len(decoded), len(data))
	}
	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("Byte %d mismatch: %d vs %d", i, decoded[i], data[i])
		}
	}
}

func TestEncryptDecryptFilename(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "")
	for _, enc := range []string{"base32", "base64"} {
		t.Run(enc, func(t *testing.T) {
			original := "TEST_FILE.txt"
			encrypted, err := EncryptFilename(original, keys, enc)
			if err != nil {
				t.Fatalf("EncryptFilename failed: %v", err)
			}
			if encrypted == original {
				t.Error("EncryptFilename returned same string")
			}
			decrypted, err := DecryptFilename(encrypted, keys, enc)
			if err != nil {
				t.Fatalf("DecryptFilename failed: %v", err)
			}
			if decrypted != original {
				t.Errorf("Expected '%s', got '%s'", original, decrypted)
			}
		})
	}
}

func TestEncryptDecryptFile(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "")
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "test.txt")
	outputFile := filepath.Join(tmpDir, "test.txt.enc")
	decryptedFile := filepath.Join(tmpDir, "test_dec.txt")

	originalContent := []byte("Hello, World! This is a test file with some content.")
	if err := os.WriteFile(inputFile, originalContent, 0644); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(inputFile, outputFile, keys); err != nil {
		t.Fatal(err)
	}

	encInfo, _ := os.Stat(outputFile)
	if encInfo.Size() <= int64(len(originalContent)) {
		t.Error("Encrypted file should be larger than original")
	}

	if err := DecryptFile(outputFile, decryptedFile, keys); err != nil {
		t.Fatal(err)
	}

	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(decryptedContent) != string(originalContent) {
		t.Errorf("Content mismatch: got '%s'", string(decryptedContent))
	}
}

func TestEncryptDecryptFileWithSalt(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "mysalt")
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "test.txt")
	outputFile := filepath.Join(tmpDir, "test.txt.enc")
	decryptedFile := filepath.Join(tmpDir, "test_dec.txt")

	originalContent := []byte("Test content with salt")
	os.WriteFile(inputFile, originalContent, 0644)

	if err := EncryptFile(inputFile, outputFile, keys); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(outputFile, decryptedFile, keys); err != nil {
		t.Fatal(err)
	}

	decrypted, _ := os.ReadFile(decryptedFile)
	if string(decrypted) != string(originalContent) {
		t.Error("Content mismatch with salt")
	}
}

func TestEncryptDecryptEmptyFile(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "")
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "empty.txt")
	outputFile := filepath.Join(tmpDir, "empty.txt.enc")
	decryptedFile := filepath.Join(tmpDir, "empty_dec.txt")

	os.WriteFile(inputFile, []byte{}, 0644)

	if err := EncryptFile(inputFile, outputFile, keys); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(outputFile, decryptedFile, keys); err != nil {
		t.Fatal(err)
	}

	decrypted, _ := os.ReadFile(decryptedFile)
	if len(decrypted) != 0 {
		t.Error("Expected empty file")
	}
}

func TestDecryptFileWrongPassword(t *testing.T) {
	keys, _ := DeriveKeys("correct_password", "")
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "test.txt")
	outputFile := filepath.Join(tmpDir, "test.txt.enc")

	os.WriteFile(inputFile, []byte("secret data"), 0644)
	EncryptFile(inputFile, outputFile, keys)

	wrongKeys, _ := DeriveKeys("wrong_password", "")
	decryptedFile := filepath.Join(tmpDir, "test_dec.txt")
	err := DecryptFile(outputFile, decryptedFile, wrongKeys)
	if err == nil {
		t.Error("Expected decryption to fail with wrong password")
	}
}

func TestDecryptFileCorruptedMagic(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "")
	tmpDir := t.TempDir()

	corruptedFile := filepath.Join(tmpDir, "corrupted.txt")
	decryptedFile := filepath.Join(tmpDir, "dec.txt")

	os.WriteFile(corruptedFile, []byte("NOT_RCLONE_MAGIC_HERE_BECAUSE_THIS_IS_WRONG"), 0644)
	err := DecryptFile(corruptedFile, decryptedFile, keys)
	if err == nil {
		t.Error("Expected error for corrupted file")
	}
}

func TestEncryptDecryptRoundtripWithCustomEncoding(t *testing.T) {
	keys, _ := DeriveKeys("testpassword", "")
	tmpDir := t.TempDir()

	for _, enc := range []string{"base32", "base64"} {
		t.Run(enc, func(t *testing.T) {
			inputFile := filepath.Join(tmpDir, "roundtrip_"+enc+".txt")
			outputFile := filepath.Join(tmpDir, "roundtrip_"+enc+".txt.enc")
			decryptedFile := filepath.Join(tmpDir, "roundtrip_"+enc+"_dec.txt")

			originalContent := []byte("Roundtrip test with encoding: " + enc)
			os.WriteFile(inputFile, originalContent, 0644)

			if err := EncryptFile(inputFile, outputFile, keys); err != nil {
				t.Fatal(err)
			}
			if err := DecryptFile(outputFile, decryptedFile, keys); err != nil {
				t.Fatal(err)
			}

			decrypted, _ := os.ReadFile(decryptedFile)
			if string(decrypted) != string(originalContent) {
				t.Errorf("Roundtrip failed for encoding %s", enc)
			}
		})
	}
}

func TestDecryptKnownFiles(t *testing.T) {
	password := "Testpassword1"
	keys, err := DeriveKeys(password, "")
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := t.TempDir()

	t.Run("base32_filename", func(t *testing.T) {
		decryptedName, err := DecryptFilename("kr9tu4e1da4u3nifdd99g9tf5o", keys, "base32")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Decrypted filename: %s", decryptedName)

		outputFile := filepath.Join(tmpDir, decryptedName)
		if err := DecryptFile("kr9tu4e1da4u3nifdd99g9tf5o", outputFile, keys); err != nil {
			t.Fatal(err)
		}
		content, _ := os.ReadFile(outputFile)
		if len(content) == 0 {
			t.Error("Decrypted file is empty")
		}
		t.Logf("Decrypted content: %s", string(content))
	})

	t.Run("base64_filename", func(t *testing.T) {
		decryptedName, err := DecryptFilename("Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY", keys, "base64")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Decrypted filename: %s", decryptedName)

		outputFile := filepath.Join(tmpDir, decryptedName)
		if err := DecryptFile("Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY", outputFile, keys); err != nil {
			t.Fatal(err)
		}
		content, _ := os.ReadFile(outputFile)
		if len(content) == 0 {
			t.Error("Decrypted file is empty")
		}
		t.Logf("Decrypted content: %s", string(content))
	})
}
