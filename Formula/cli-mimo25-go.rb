class CliMimo25Go < Formula
  desc "CLI tool to encrypt and decrypt files using rclone-compatible encryption"
  homepage "https://github.com/llm-supermarket/cli-mimo25-go"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v0.1.0/cli-mimo25-go-darwin-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v0.1.0/cli-mimo25-go-darwin-amd64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v0.1.0/cli-mimo25-go-linux-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v0.1.0/cli-mimo25-go-linux-amd64.tar.gz"
      sha256 ""
    end
  end

  def install
    bin.install "cli-mimo25-go-darwin-arm64" => "cli-mimo25-go" if OS.mac? && Hardware::CPU.arm?
    bin.install "cli-mimo25-go-darwin-amd64" => "cli-mimo25-go" if OS.mac? && !Hardware::CPU.arm?
    bin.install "cli-mimo25-go-linux-arm64" => "cli-mimo25-go" if OS.linux? && Hardware::CPU.arm?
    bin.install "cli-mimo25-go-linux-amd64" => "cli-mimo25-go" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "cli-mimo25-go #{version}", shell_output("#{bin}/cli-mimo25-go --version")
  end
end
