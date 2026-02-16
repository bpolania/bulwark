class Bulwark < Formula
  desc "Open-source governance layer for AI agents"
  homepage "https://github.com/bpolania/bulwark"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/bpolania/bulwark/releases/download/v0.1.0/bulwark-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/bpolania/bulwark/releases/download/v0.1.0/bulwark-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/bpolania/bulwark/releases/download/v0.1.0/bulwark-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
    on_intel do
      url "https://github.com/bpolania/bulwark/releases/download/v0.1.0/bulwark-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_ACTUAL_SHA256"
    end
  end

  def install
    bin.install "bulwark"
  end

  test do
    assert_match "bulwark", shell_output("#{bin}/bulwark --version")
  end
end
