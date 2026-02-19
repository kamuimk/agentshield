# Homebrew formula for AgentShield
# Install: brew install kamuimk/tap/agentshield
#
# This formula is intended for use in a Homebrew tap repository.
# Copy this file to homebrew-tap/Formula/agentshield.rb and update
# the version/sha256 values on each release.

class Agentshield < Formula
  desc "AI Agent Egress Firewall - Default-deny egress control for AI agents"
  homepage "https://github.com/kamuimk/agentshield"
  license "Apache-2.0"
  version "1.0.0"

  on_macos do
    on_intel do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_INTEL"
    end

    on_arm do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_SHA256_MACOS_ARM"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_INTEL"
    end

    on_arm do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agentshield --version")
  end
end
