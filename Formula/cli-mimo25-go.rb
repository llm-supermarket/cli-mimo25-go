class CliMimo25Go < Formula
  desc "CLI tool to encrypt and decrypt files using rclone-compatible encryption"
  homepage "https://github.com/llm-supermarket/cli-mimo25-go"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v1.0.0/cli-mimo25-go-darwin-arm64.tar.gz"
      sha256 "180f732c94137006e8ff21db21a1a80353088aeb0542905e9f527f5485ac2f77"
    else
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v1.0.0/cli-mimo25-go-darwin-amd64.tar.gz"
      sha256 "f65d08b4b96b3b035ef1156e2ad9beda61a1096927f5c2a617e3c9622aac6664"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v1.0.0/cli-mimo25-go-linux-arm64.tar.gz"
      sha256 "4420c1b41c93d1d0179b5aac25c22e06e8d6b6f0c0eefd685eaa25040de8202a"
    else
      url "https://github.com/llm-supermarket/cli-mimo25-go/releases/download/v1.0.0/cli-mimo25-go-linux-amd64.tar.gz"
      sha256 "e8fbc318f6b81770d14008e20f412c8d72b2209a3fb884131d982c3c9dfc20ea"
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