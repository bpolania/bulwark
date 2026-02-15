//! `bulwark ca export` — print the CA certificate PEM to stdout.

use std::path::Path;

use anyhow::{Context, Result};
use bulwark_config::{expand_tilde, load_config};

/// Export the CA certificate PEM to stdout.
pub fn export(config_path: &Path) -> Result<()> {
    let config = load_config(config_path).context("loading configuration")?;
    let ca_dir = expand_tilde(&config.proxy.tls.ca_dir);
    let ca_pem_path = Path::new(&ca_dir).join("ca.pem");

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
