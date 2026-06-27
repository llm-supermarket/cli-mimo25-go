package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVersion(t *testing.T) {
	build(t)
	out := runCLI(t, "--version")
	if !strings.Contains(out, "cli-mimo25-go") {
		t.Errorf("Expected version output, got: %s", out)
	}
}

func TestCLIHelp(t *testing.T) {
	build(t)
	out := runCLI(t, "--help")
	if !strings.Contains(out, "encrypt") || !strings.Contains(out, "decrypt") {
		t.Errorf("Expected help output with encrypt/decrypt, got: %s", out)
	}
}

func TestCLIEncryptDecryptRoundtrip(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "TEST_FILE.txt")
	originalContent := []byte("abandon ability able about above absent absorb abstract absurd abuse access accident\n")
	os.WriteFile(inputFile, originalContent, 0644)

	encOutput := filepath.Join(tmpDir, "encrypted.bin")
	runCLINoFail(t, "encrypt", "-i", inputFile, "-o", encOutput, "--password", "Testpass1")

	decOutput := filepath.Join(tmpDir, "decrypted.txt")
	runCLINoFail(t, "decrypt", "-i", encOutput, "-o", decOutput, "--password", "Testpass1")

	decrypted, _ := os.ReadFile(decOutput)
	if string(decrypted) != string(originalContent) {
		t.Errorf("Content mismatch: got '%s'", string(decrypted))
	}
}

func TestCLIEncryptDecryptWithSalt(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "salt_test.txt")
	originalContent := []byte("test content with salt value")
	os.WriteFile(inputFile, originalContent, 0644)

	encOutput := filepath.Join(tmpDir, "encrypted.bin")
	runCLINoFail(t, "encrypt", "-i", inputFile, "-o", encOutput, "--password", "Testpass1", "--salt", "mysalt123")

	decOutput := filepath.Join(tmpDir, "decrypted.txt")
	runCLINoFail(t, "decrypt", "-i", encOutput, "-o", decOutput, "--password", "Testpass1", "--salt", "mysalt123")

	decrypted, _ := os.ReadFile(decOutput)
	if string(decrypted) != string(originalContent) {
		t.Errorf("Content mismatch with salt: got '%s'", string(decrypted))
	}
}

func TestCLIEncryptDecryptWithBase64Encoding(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "base64_test.txt")
	originalContent := []byte("base64 encoding test")
	os.WriteFile(inputFile, originalContent, 0644)

	encOutput := filepath.Join(tmpDir, "encrypted.bin")
	runCLINoFail(t, "encrypt", "-i", inputFile, "-o", encOutput, "--password", "Testpass1", "--filename-encoding", "base64")

	decOutput := filepath.Join(tmpDir, "decrypted.txt")
	runCLINoFail(t, "decrypt", "-i", encOutput, "-o", decOutput, "--password", "Testpass1", "--filename-encoding", "base64")

	decrypted, _ := os.ReadFile(decOutput)
	if string(decrypted) != string(originalContent) {
		t.Errorf("Content mismatch with base64: got '%s'", string(decrypted))
	}
}

func TestCLIFilenameEncryption(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()

	inputFile := filepath.Join(tmpDir, "TEST_FILE.txt")
	originalContent := []byte("filename encryption test content")
	os.WriteFile(inputFile, originalContent, 0644)

	runCLINoFail(t, "encrypt", "-i", inputFile, "--password", "Testpass1")

	encryptedName := "TEST_FILE.txt"
	entries, _ := os.ReadDir(tmpDir)
	found := false
	for _, e := range entries {
		if e.Name() != "TEST_FILE.txt" {
			found = true
			encryptedName = e.Name()
			break
		}
	}
	if !found {
		t.Fatal("Expected encrypted filename to be different from original")
	}
	t.Logf("Encrypted filename: %s", encryptedName)

	encryptedPath := filepath.Join(tmpDir, encryptedName)
	decryptedOutput := filepath.Join(tmpDir, "original.txt")
	runCLINoFail(t, "decrypt", "-i", encryptedPath, "-o", decryptedOutput, "--password", "Testpass1")

	decrypted, _ := os.ReadFile(decryptedOutput)
	if string(decrypted) != string(originalContent) {
		t.Errorf("Content mismatch: got '%s'", string(decrypted))
	}
}

func TestCLIDecryptKnownFiles(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()

	t.Run("base32", func(t *testing.T) {
		repoRoot := findRepoRoot(t)
		inputFile := filepath.Join(repoRoot, "kr9tu4e1da4u3nifdd99g9tf5o")
		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			t.Skip("Test file not found")
		}

		runCLINoFail(t, "decrypt", "-i", inputFile, "-o", filepath.Join(tmpDir, "test_base32.txt"),
			"--password", "Testpassword1")

		content, _ := os.ReadFile(filepath.Join(tmpDir, "test_base32.txt"))
		if len(content) == 0 {
			t.Error("Decrypted file is empty")
		}
		t.Logf("Decrypted content: %s", string(content))
	})

	t.Run("base64", func(t *testing.T) {
		repoRoot := findRepoRoot(t)
		inputFile := filepath.Join(repoRoot, "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY")
		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			t.Skip("Test file not found")
		}

		runCLINoFail(t, "decrypt", "-i", inputFile, "-o", filepath.Join(tmpDir, "test_base64.txt"),
			"--password", "Testpassword1", "--filename-encoding", "base64")

		content, _ := os.ReadFile(filepath.Join(tmpDir, "test_base64.txt"))
		if len(content) == 0 {
			t.Error("Decrypted file is empty")
		}
		t.Logf("Decrypted content: %s", string(content))
	})
}

func TestCLINoInputFile(t *testing.T) {
	build(t)
	_, err := runCLIError(t, "encrypt")
	if err == nil {
		t.Error("Expected error when no input file specified")
	}
}

func TestCLINonexistentInputFile(t *testing.T) {
	build(t)
	_, err := runCLIError(t, "encrypt", "-i", "nonexistent.txt", "--password", "test")
	if err == nil {
		t.Error("Expected error for nonexistent input file")
	}
}

func TestCLIInvalidEncoding(t *testing.T) {
	build(t)
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(inputFile, []byte("test"), 0644)
	_, err := runCLIError(t, "encrypt", "-i", inputFile, "--password", "test", "--filename-encoding", "hex")
	if err == nil {
		t.Error("Expected error for invalid encoding")
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cli-mimo25-go-test")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = findRepoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\n%s", err, out)
	}
	return binary
}

func build(t *testing.T) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", "cli-mimo25-go.exe", ".")
	cmd.Dir = findRepoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\n%s", err, out)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find repo root")
		}
		dir = parent
	}
}

func runCLI(t *testing.T, args ...string) string {
	t.Helper()
	binary := filepath.Join(findRepoRoot(t), "cli-mimo25-go.exe")
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	t.Logf("Output: %s", string(out))
	_ = err
	return string(out)
}

func runCLINoFail(t *testing.T, args ...string) {
	t.Helper()
	binary := filepath.Join(findRepoRoot(t), "cli-mimo25-go.exe")
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI command failed: %v\nOutput: %s", err, string(out))
	}
	t.Logf("Output: %s", string(out))
}

func runCLIError(t *testing.T, args ...string) (string, error) {
	t.Helper()
	binary := filepath.Join(findRepoRoot(t), "cli-mimo25-go.exe")
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
