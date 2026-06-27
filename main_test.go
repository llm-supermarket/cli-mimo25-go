package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func repoRoot(t *testing.T) string {
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
			t.Fatal("could not find repo root")
		}
		dir = parent
	}
}

func TestCLIDecryptWithPassword(t *testing.T) {
	binPath := buildCLI(t)
	root := repoRoot(t)
	input := filepath.Join(root, "kr9tu4e1da4u3nifdd99g9tf5o")
	output := filepath.Join(t.TempDir(), "decrypted.txt")

	cmd := exec.Command(binPath, "--password", "Testpassword1", "-i", input, "-o", output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("output file is empty")
	}
	t.Logf("Decrypted content: %s", string(data))
}

func TestCLIDecryptBase64WithPassword(t *testing.T) {
	binPath := buildCLI(t)
	root := repoRoot(t)
	input := filepath.Join(root, "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY")
	output := filepath.Join(t.TempDir(), "decrypted_base64.txt")

	cmd := exec.Command(binPath, "--password", "Testpassword1", "-i", input, "-o", output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("output file is empty")
	}
	t.Logf("Decrypted base64 content: %s", string(data))
}

func TestCLIEncryptDecryptRoundtrip(t *testing.T) {
	binPath := buildCLI(t)
	dir := t.TempDir()

	plaintext := "## Test FILE\n\nabandon ability able about above absent absorb abstract absurd abuse access accident\n"
	inputPath := filepath.Join(dir, "TEST_FILE.txt")
	encryptedPath := filepath.Join(dir, "TEST_FILE.txt.bin")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte(plaintext), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "--password", "MySecret123", "-i", inputPath, "-o", encryptedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	t.Logf("Encrypt output: %s", out)

	cmd = exec.Command(binPath, "--password", "MySecret123", "-i", encryptedPath, "-o", decryptedPath)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("failed to read decrypted: %v", err)
	}
	if string(data) != plaintext {
		t.Errorf("roundtrip mismatch:\ngot:  %q\nwant: %q", string(data), plaintext)
	}
}

func TestCLIEncryptDecryptWithSalt(t *testing.T) {
	binPath := buildCLI(t)
	dir := t.TempDir()

	plaintext := "test content with salt\n"
	inputPath := filepath.Join(dir, "input.txt")
	encryptedPath := filepath.Join(dir, "input.txt.bin")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte(plaintext), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "--password", "Password1", "-s", "mysalt", "-i", inputPath, "-o", encryptedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	t.Logf("Encrypt with salt output: %s", out)

	cmd = exec.Command(binPath, "--password", "Password1", "-s", "mysalt", "-i", encryptedPath, "-o", decryptedPath)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(data) != plaintext {
		t.Errorf("roundtrip with salt mismatch:\ngot:  %q\nwant: %q", string(data), plaintext)
	}
}

func TestCLIEncryptDecryptBase64Encoding(t *testing.T) {
	binPath := buildCLI(t)
	dir := t.TempDir()

	plaintext := "base64 encoding test\n"
	inputPath := filepath.Join(dir, "input.txt")
	encryptedPath := filepath.Join(dir, "input.txt.bin")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte(plaintext), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "--password", "Pass123", "-e", "base64", "-i", inputPath, "-o", encryptedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt with base64 failed: %v\n%s", err, out)
	}
	t.Logf("Encrypt base64 output: %s", out)

	cmd = exec.Command(binPath, "--password", "Pass123", "-e", "base64", "-i", encryptedPath, "-o", decryptedPath)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt with base64 failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(data) != plaintext {
		t.Errorf("base64 roundtrip mismatch:\ngot:  %q\nwant: %q", string(data), plaintext)
	}
}

func TestCLIDecryptWithSalt(t *testing.T) {
	binPath := buildCLI(t)
	dir := t.TempDir()

	plaintext := "salted content\n"
	inputPath := filepath.Join(dir, "input.txt")
	encryptedPath := filepath.Join(dir, "input.txt.bin")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte(plaintext), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binPath, "--password", "Pass1", "-s", "saltvalue", "-i", inputPath, "-o", encryptedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	cmd = exec.Command(binPath, "--password", "Pass1", "-s", "saltvalue", "-i", encryptedPath, "-o", decryptedPath)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}

	data, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(data) != plaintext {
		t.Errorf("decrypt with salt mismatch:\ngot:  %q\nwant: %q", string(data), plaintext)
	}
}

func TestCLINoInputFile(t *testing.T) {
	binPath := buildCLI(t)
	cmd := exec.Command(binPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when no input file specified")
	}
	t.Logf("Expected error output: %s", out)
}

func TestCLIWrongPassword(t *testing.T) {
	binPath := buildCLI(t)
	dir := t.TempDir()

	plaintext := "secret data\n"
	inputPath := filepath.Join(dir, "input.txt")
	encryptedPath := filepath.Join(dir, "input.txt.bin")
	decryptedPath := filepath.Join(dir, "decrypted.txt")

	os.WriteFile(inputPath, []byte(plaintext), 0644)

	cmd := exec.Command(binPath, "--password", "CorrectPass", "-i", inputPath, "-o", encryptedPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	cmd = exec.Command(binPath, "--password", "WrongPass", "-i", encryptedPath, "-o", decryptedPath)
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error when decrypting with wrong password")
	}
	t.Logf("Expected error: %s", out)
}

func TestCLIVersion(t *testing.T) {
	binPath := buildCLI(t)
	cmd := exec.Command(binPath, "--version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v\n%s", err, out)
	}
	t.Logf("Version output: %s", out)
}

func TestCLIEncryptDecryptRcloneFiles(t *testing.T) {
	binPath := buildCLI(t)
	root := repoRoot(t)
	dir := t.TempDir()

	output1 := filepath.Join(dir, "decrypted_base32.txt")
	cmd := exec.Command(binPath, "--password", "Testpassword1", "-i", filepath.Join(root, "kr9tu4e1da4u3nifdd99g9tf5o"), "-o", output1)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt base32 file failed: %v\n%s", err, out)
	}

	data1, _ := os.ReadFile(output1)
	t.Logf("Base32 decrypted: %q", string(data1))

	output2 := filepath.Join(dir, "decrypted_base64_name.txt")
	cmd = exec.Command(binPath, "--password", "Testpassword1", "-i", filepath.Join(root, "Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY"), "-o", output2)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt base64 file failed: %v\n%s", err, out)
	}

	data2, _ := os.ReadFile(output2)
	t.Logf("Base64 name decrypted: %q", string(data2))

	if string(data1) != string(data2) {
		t.Errorf("both files should decrypt to same content")
	}
}

func buildCLI(t *testing.T) string {
	t.Helper()
	binName := "rclone-encrypt-mimo25"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)

	root := repoRoot(t)

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

 PATH := os.Getenv("PATH")
	t.Setenv("PATH", filepath.Dir(binPath)+string(os.PathListSeparator)+PATH)
	return binPath
}
