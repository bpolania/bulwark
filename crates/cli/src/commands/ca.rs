//! `bulwark ca` — CA certificate management commands.

use std::path::Path;

use anyhow::{Context, Result};
use bulwark_config::{expand_tilde, load_config};

/// Resolve the CA PEM path from config.
fn resolve_ca_pem_path(config_path: &Path) -> Result<std::path::PathBuf> {
    let config = load_config(config_path).context("loading configuration")?;
    let ca_dir = expand_tilde(&config.proxy.tls.ca_dir);
    Ok(std::path::PathBuf::from(ca_dir).join("ca.pem"))
}

/// Export the CA certificate PEM to stdout.
pub fn export(config_path: &Path) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        anyhow::bail!(
            "No CA certificate found at {}. Run `bulwark init` or `bulwark proxy start` first.",
            ca_pem_path.display()
        );
    }

    let pem = std::fs::read_to_string(&ca_pem_path)
        .with_context(|| format!("reading {}", ca_pem_path.display()))?;

    print!("{pem}");
    Ok(())
}

/// Print the absolute path to the CA certificate PEM file.
pub fn path(config_path: &Path) -> Result<()> {
    let ca_pem_path = resolve_ca_pem_path(config_path)?;

    if !ca_pem_path.exists() {
        eprintln!("CA certificate not found. Run 'bulwark init' first.");
        std::process::exit(1);
    }

    let absolute = ca_pem_path
        .canonicalize()
        .with_context(|| format!("resolving absolute path for {}", ca_pem_path.display()))?;

    println!("{}", absolute.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_path_returns_pem_path() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();

        // Write a dummy ca.pem.
        let ca_pem = ca_dir.join("ca.pem");
        std::fs::write(
            &ca_pem,
            "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        // Write a config pointing to this CA dir.
        let config_path = dir.path().join("bulwark.yaml");
        std::fs::write(
            &config_path,
            format!(
                "proxy:\n  listen_address: \"127.0.0.1:0\"\n  tls:\n    ca_dir: \"{}\"\n",
                ca_dir.display()
            ),
        )
        .unwrap();

        // Resolve the path.
        let resolved = resolve_ca_pem_path(&config_path).unwrap();
        assert!(resolved.exists(), "resolved path should exist on disk");
        assert!(
            resolved.to_str().unwrap().ends_with("ca.pem"),
            "path should end with ca.pem, got: {}",
            resolved.display()
        );

        // Verify canonicalize works (the path handler uses it).
        let absolute = resolved.canonicalize().unwrap();
        assert!(absolute.is_absolute(), "path should be absolute");
        assert!(
            absolute.to_str().unwrap().ends_with("ca.pem"),
            "absolute path should end with ca.pem"
        );
    }
}
