use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dnsforge", about = "Declarative DNS zone manager")]
pub struct Cli {
    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Color output
    #[arg(long, default_value = "auto", global = true)]
    pub color: ColorMode,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Synchronize DNS zones
    Apply {
        /// Zone definition files
        #[arg(required = true)]
        files: Vec<PathBuf>,

        /// Show changes without applying
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Apply changes without confirmation prompt
        #[arg(long)]
        no_confirm: bool,

        /// Only sync named zone(s) (repeatable)
        #[arg(long = "zone")]
        zones: Vec<String>,
    },

    /// Validate zone files without connecting
    Check {
        /// Zone definition files
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },

    /// Manage TSIG keys
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Import a TSIG key from a BIND key file
    Add {
        /// Key file path (omit or use - for stdin)
        file: Option<PathBuf>,

        /// Override the reference name (default: TSIG key name from file)
        #[arg(long)]
        name: Option<String>,
    },

    /// List stored keys
    List,

    /// Remove a stored key
    Remove {
        /// Key name
        name: String,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}
