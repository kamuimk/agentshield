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
  # SHA256 values are automatically computed in the release workflow.
  # Update these after each release using the values from the GitHub Release page.

  on_macos do
    on_intel do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-x86_64-apple-darwin.tar.gz"
      sha256 "36a9e1eb89fea38c08539031a8860aa0154fa2dc4cb97d691b65c51a8374e512"
    end

    on_arm do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-aarch64-apple-darwin.tar.gz"
      sha256 "d27e27f221f5dab2f2912b14da4b9b319df006e2f87af8784c9f5599f8ee891a"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "51c068a68f1129dcb9074518b222b3d73a4db36054cdefdaf322816d4d402fe6"
    end

    on_arm do
      url "https://github.com/kamuimk/agentshield/releases/download/v#{version}/agentshield-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "6e46c90be26eda96d676cf2183bfb0dc565a00d6dbb79cae1ba152ed3f1c8e77"
    end
  end

  def install
    bin.install "agentshield"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/agentshield --version")
  end
end
