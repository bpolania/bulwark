//! `bulwark init [path]` — scaffold a new Bulwark project directory.

use std::path::Path;

use anyhow::{Context, Result};

/// Run the `init` command: create project scaffolding in the target directory.
pub fn run(path: Option<&Path>) -> Result<()> {
    let target = path.unwrap_or_else(|| Path::new("."));

    std::fs::create_dir_all(target)
        .with_context(|| format!("creating directory {}", target.display()))?;

    // Write default config.
    let config_path = target.join("bulwark.yaml");
    if !config_path.exists() {
        std::fs::write(&config_path, include_str!("../../../../bulwark.yaml"))
            .context("writing bulwark.yaml")?;
        println!("  created {}", config_path.display());
    }

    // Create policies directory with placeholder.
    let policies_dir = target.join("policies");
    std::fs::create_dir_all(&policies_dir).context("creating policies/")?;
    let global_policy = policies_dir.join("global.yaml");
    if !global_policy.exists() {
        std::fs::write(
            &global_policy,
            "# Bulwark global policy\n# See documentation for policy syntax.\n",
        )
        .context("writing global.yaml")?;
        println!("  created {}", global_policy.display());
    }

    // Create secrets directory.
    let secrets_dir = target.join("secrets");
    std::fs::create_dir_all(&secrets_dir).context("creating secrets/")?;
    let gitkeep = secrets_dir.join(".gitkeep");
    if !gitkeep.exists() {
        std::fs::write(&gitkeep, "").context("writing .gitkeep")?;
    }

    // Generate CA if it doesn't already exist.
    let ca_dir = bulwark_config::expand_tilde("~/.bulwark/ca");
    let ca_cert = Path::new(&ca_dir).join("ca.pem");
    if !ca_cert.exists() {
        // Generating the CA has the side-effect of writing the files.
        bulwark_proxy::tls::TlsState::new("~/.bulwark/ca").context("generating CA")?;
        println!("  generated CA in {ca_dir}");
    }

    println!();
    println!("Bulwark project initialised in {}", target.display());
    println!();
    println!("Next steps:");
    println!("  1. Edit bulwark.yaml to configure the proxy");
    println!("  2. Trust the CA certificate at {}/ca.pem", ca_dir);
    println!("  3. Run `bulwark proxy start` to launch the proxy");

    Ok(())
}
