param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)

$repo = "llm-supermarket/cli-mimo25-go"
$platforms = @("darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64")
$formulaPath = "$PSScriptRoot/Formula/cli-mimo25-go.rb"
$base = "https://github.com/$repo/releases/download/v$Version"

$hash = @{}
foreach ($platform in $platforms) {
    $url = "$base/cli-mimo25-go-$platform.tar.gz"
    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "cli-mimo25-go-$platform.tar.gz"

    Write-Host "Downloading $url ..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile

    $hash[$platform] = (Get-FileHash -Path $tempFile -Algorithm SHA256).Hash.ToLower()
    Write-Host "SHA256 for ${platform}: $($hash[$platform])"

    Remove-Item $tempFile
}

$formula = @"
class CliMimo25Go < Formula
  desc "CLI tool to encrypt and decrypt files using rclone-compatible encryption"
  homepage "https://github.com/$repo"
  version "$Version"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/cli-mimo25-go-darwin-arm64.tar.gz"
      sha256 "$($hash['darwin-arm64'])"
    else
      url "$base/cli-mimo25-go-darwin-amd64.tar.gz"
      sha256 "$($hash['darwin-amd64'])"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/cli-mimo25-go-linux-arm64.tar.gz"
      sha256 "$($hash['linux-arm64'])"
    else
      url "$base/cli-mimo25-go-linux-amd64.tar.gz"
      sha256 "$($hash['linux-amd64'])"
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
"@

Set-Content -Path $formulaPath -Value $formula -NoNewline
Write-Host "Wrote $formulaPath for version $Version"
