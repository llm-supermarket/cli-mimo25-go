class RcloneEncryptMimo25 < Formula
  desc "CLI tool to encrypt and decrypt files using rclone encryption defaults"
  homepage "https://github.com/llm-supermarket-org/cli-mimo25-go"
  version "1.0.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket-org/cli-mimo25-go/releases/download/v1.0.0/rclone-encrypt-mimo25-darwin-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket-org/cli-mimo25-go/releases/download/v1.0.0/rclone-encrypt-mimo25-darwin-amd64.tar.gz"
      sha256 ""
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/llm-supermarket-org/cli-mimo25-go/releases/download/v1.0.0/rclone-encrypt-mimo25-linux-arm64.tar.gz"
      sha256 ""
    else
      url "https://github.com/llm-supermarket-org/cli-mimo25-go/releases/download/v1.0.0/rclone-encrypt-mimo25-linux-amd64.tar.gz"
      sha256 ""
    end
  end

  def install
    bin.install "rclone-encrypt-mimo25-darwin-arm64" => "rclone-encrypt-mimo25" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-mimo25-darwin-amd64" => "rclone-encrypt-mimo25" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-mimo25-linux-arm64" => "rclone-encrypt-mimo25" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-mimo25-linux-amd64" => "rclone-encrypt-mimo25" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-mimo25", shell_output("#{bin}/rclone-encrypt-mimo25 --version")
  end
end
