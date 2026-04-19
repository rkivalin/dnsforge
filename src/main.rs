mod cli;
mod diff;
mod display;
mod dns;
mod error;
mod keystore;
mod script;
mod sync;

use clap::Parser;

use cli::{Cli, Command, KeyAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Set up logging
    if cli.verbose > 0 {
        let filter = match cli.verbose {
            1 => "dnsforge=debug",
            2 => "dnsforge=trace",
            _ => "trace",
        };
        let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| filter.to_string());
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }

    let use_color = display::should_use_color(&cli.color);

    match cli.command {
        Command::Apply {
            files,
            dry_run,
            no_confirm,
            zones,
        } => {
            let has_changes = sync::run(&files, dry_run, no_confirm, &zones, use_color).await?;
            if dry_run && has_changes {
                std::process::exit(1);
            }
        }

        Command::Check { files } => {
            sync::check(&files)?;
        }

        Command::Key { action } => match action {
            KeyAction::Add { file, name } => {
                let info = keystore::add_key(file.as_deref(), name.as_deref())?;
                if info.name != info.tsig_name {
                    eprintln!(
                        "Imported key '{}' (tsig: {}, {}{})",
                        info.name,
                        info.tsig_name,
                        info.algorithm,
                        if info.encrypted { ", encrypted" } else { "" }
                    );
                } else {
                    eprintln!(
                        "Imported key '{}' ({}{})",
                        info.name,
                        info.algorithm,
                        if info.encrypted { ", encrypted" } else { "" }
                    );
                }
            }

            KeyAction::List => {
                let keys = keystore::list_keys()?;
                if keys.is_empty() {
                    eprintln!("No keys stored.");
                } else {
                    for k in &keys {
                        let enc = if k.encrypted { " [encrypted]" } else { "" };
                        if k.name != k.tsig_name {
                            println!("{} (tsig: {}, {}){}", k.name, k.tsig_name, k.algorithm, enc);
                        } else {
                            println!("{} ({}){}", k.name, k.algorithm, enc);
                        }
                    }
                }
            }

            KeyAction::Remove { name } => {
                keystore::remove_key(&name)?;
                eprintln!("Removed key '{name}'");
            }
        },
    }

    Ok(())
}
