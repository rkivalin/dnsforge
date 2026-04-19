use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("DNS error: {0}")]
    Dns(String),

    #[error("script error in {file}: {message}")]
    Script { file: String, message: String },

    #[error("config error: {0}")]
    Config(String),

    #[error("key {name} not found in {path}")]
    KeyNotFound { name: String, path: PathBuf },

    #[error("key error: {0}")]
    Key(String),


    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
