# Homebrew Tap for Bulwark

Open-source governance layer for AI agents.

## Install

```bash
brew tap bpolania/tap
brew install bulwark
```

Or in one command:

```bash
brew install bpolania/tap/bulwark
```

## Upgrade

```bash
brew update
brew upgrade bulwark
```

## Uninstall

```bash
brew uninstall bulwark
brew untap bpolania/tap
```

## Publishing a new release

1. Build release binaries for all targets:
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
   - `aarch64-unknown-linux-gnu`
   - `x86_64-unknown-linux-gnu`

2. Create `.tar.gz` archives containing the `bulwark` binary.

3. Upload them to a GitHub Release tagged `vX.Y.Z`.

4. Compute SHA256 checksums:
   ```bash
   shasum -a 256 bulwark-*.tar.gz
   ```

5. Update `Formula/bulwark.rb` with the new version, URLs, and SHA256 values.

6. Commit and push to this repository.
