use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::Argon2;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;

use crate::error::{Error, Result};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// A parsed TSIG key ready for use.
#[derive(Debug, Clone)]
pub struct TsigKey {
    /// TSIG key name (sent to DNS server)
    pub tsig_name: String,
    /// Algorithm (e.g. "hmac-sha256")
    pub algorithm: String,
    /// Decoded secret bytes
    pub secret: Vec<u8>,
}

/// A key entry as stored in the keys file.
#[derive(Debug, Clone)]
struct KeyEntry {
    name: String,
    tsig_name: String,
    algorithm: String,
    encrypted: bool,
    /// Base64-encoded key data (plain secret or encrypted blob)
    data: String,
}

/// Password cache for decrypting multiple keys without repeated prompts.
pub struct PasswordCache {
    passwords: Vec<String>,
}

impl PasswordCache {
    pub fn new() -> Self {
        Self {
            passwords: Vec::new(),
        }
    }

    /// Try to decrypt key data with cached passwords, then prompt if needed.
    fn decrypt(&mut self, entry: &KeyEntry) -> Result<Vec<u8>> {
        // Try cached passwords first
        for pw in &self.passwords {
            if let Ok(secret) = decrypt_secret(&entry.data, pw) {
                return Ok(secret);
            }
        }

        // Prompt for password
        let password = rpassword::prompt_password(format!("Password for key '{}': ", entry.name))
            .map_err(|e| Error::Key(format!("failed to read password: {e}")))?;

        let secret = decrypt_secret(&entry.data, &password)?;
        self.passwords.push(password);
        Ok(secret)
    }
}

// -- File path --

fn keys_file_path() -> Result<PathBuf> {
    let data_dir = dirs::data_dir()
        .ok_or_else(|| Error::Key("could not determine data directory".to_string()))?;
    Ok(data_dir.join("dnsforge").join("keys.txt"))
}

// -- Public API --

/// Info returned by list_keys for display.
pub struct KeyInfo {
    pub name: String,
    pub tsig_name: String,
    pub algorithm: String,
    pub encrypted: bool,
}

/// List all stored keys.
pub fn list_keys() -> Result<Vec<KeyInfo>> {
    let entries = read_entries()?;
    Ok(entries
        .into_iter()
        .map(|e| KeyInfo {
            name: e.name,
            tsig_name: e.tsig_name,
            algorithm: e.algorithm,
            encrypted: e.encrypted,
        })
        .collect())
}

/// Load a TSIG key by reference name, decrypting if needed.
pub fn load_key(name: &str, pw_cache: &mut PasswordCache) -> Result<TsigKey> {
    let path = keys_file_path()?;
    let entries = read_entries()?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| Error::KeyNotFound {
            name: name.to_string(),
            path: path.clone(),
        })?;

    let secret = if entry.encrypted {
        pw_cache.decrypt(entry)?
    } else {
        BASE64
            .decode(&entry.data)
            .map_err(|e| Error::Key(format!("invalid base64 in key '{}': {e}", entry.name)))?
    };

    Ok(TsigKey {
        tsig_name: entry.tsig_name.clone(),
        algorithm: entry.algorithm.clone(),
        secret,
    })
}

/// Import a key from a BIND key file (or stdin). Returns the stored key info.
pub fn add_key(file: Option<&Path>, name_override: Option<&str>) -> Result<KeyInfo> {
    let content = match file {
        Some(p) if p.to_str() != Some("-") => fs::read_to_string(p)?,
        _ => {
            let mut buf = String::new();
            io::stdin().lock().read_to_string(&mut buf)?;
            buf
        }
    };

    let parsed = parse_bind_key(&content)?;
    let ref_name = name_override.unwrap_or(&parsed.tsig_name);

    // Check for duplicates
    let mut entries = read_entries()?;
    if entries.iter().any(|e| e.name == ref_name) {
        return Err(Error::Key(format!("key '{ref_name}' already exists")));
    }

    // Prompt for encryption password
    let password = rpassword::prompt_password("Encryption password (empty for none): ")
        .map_err(|e| Error::Key(format!("failed to read password: {e}")))?;

    let (encrypted, data) = if password.is_empty() {
        (false, BASE64.encode(&parsed.secret))
    } else {
        let password2 = rpassword::prompt_password("Confirm password: ")
            .map_err(|e| Error::Key(format!("failed to read password: {e}")))?;
        if password != password2 {
            return Err(Error::Key("passwords do not match".to_string()));
        }
        (true, encrypt_secret(&parsed.secret, &password)?)
    };

    let entry = KeyEntry {
        name: ref_name.to_string(),
        tsig_name: parsed.tsig_name.clone(),
        algorithm: parsed.algorithm.clone(),
        encrypted,
        data,
    };

    entries.push(entry);
    write_entries(&entries)?;

    Ok(KeyInfo {
        name: ref_name.to_string(),
        tsig_name: parsed.tsig_name,
        algorithm: parsed.algorithm,
        encrypted,
    })
}

/// Remove a key by reference name.
pub fn remove_key(name: &str) -> Result<()> {
    let mut entries = read_entries()?;
    let before = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == before {
        return Err(Error::KeyNotFound {
            name: name.to_string(),
            path: keys_file_path()?,
        });
    }
    write_entries(&entries)
}

// -- File I/O --

/// Read all key entries from the keys file.
fn read_entries() -> Result<Vec<KeyEntry>> {
    let path = keys_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(&path)?;
    let mut entries = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        let parts: Vec<&str> = line.splitn(5, ':').collect();
        if parts.len() != 5 {
            return Err(Error::Key(format!(
                "{}:{}: invalid format (expected name:tsig-name:algorithm:encryption:data)",
                path.display(),
                lineno + 1
            )));
        }

        let encrypted = match parts[3] {
            "plain" => false,
            "encrypted" => true,
            other => {
                return Err(Error::Key(format!(
                    "{}:{}: unknown encryption type '{other}'",
                    path.display(),
                    lineno + 1
                )));
            }
        };

        entries.push(KeyEntry {
            name: parts[0].to_string(),
            tsig_name: parts[1].to_string(),
            algorithm: parts[2].to_string(),
            encrypted,
            data: parts[4].to_string(),
        });
    }

    Ok(entries)
}

/// Write all key entries to the keys file (atomically via rename).
fn write_entries(entries: &[KeyEntry]) -> Result<()> {
    let path = keys_file_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut content = String::new();
    for entry in entries {
        let enc = if entry.encrypted { "encrypted" } else { "plain" };
        content.push_str(&format!(
            "{}:{}:{}:{}:{}\n",
            entry.name, entry.tsig_name, entry.algorithm, enc, entry.data
        ));
    }

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &content)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    }

    fs::rename(&tmp_path, &path)?;
    Ok(())
}

// -- BIND key parsing --

struct ParsedBindKey {
    tsig_name: String,
    algorithm: String,
    secret: Vec<u8>,
}

/// Parse a BIND-format TSIG key file.
fn parse_bind_key(content: &str) -> Result<ParsedBindKey> {
    let mut name = None;
    let mut algorithm = None;
    let mut secret = None;

    for line in content.lines() {
        let line = line.trim();

        if let Some(rest) = line.strip_prefix("key") {
            let rest = rest.trim().trim_start_matches('"');
            if let Some(n) = rest.split('"').next() {
                name = Some(n.to_string());
            }
        }

        if let Some(rest) = line.strip_prefix("algorithm") {
            let alg = rest.trim().trim_end_matches(';').trim();
            algorithm = Some(alg.to_string());
        }

        if let Some(rest) = line.strip_prefix("secret") {
            let sec = rest
                .trim()
                .trim_matches('"')
                .trim_end_matches(';')
                .trim()
                .trim_matches('"');
            secret = Some(sec.to_string());
        }
    }

    let name = name.ok_or_else(|| Error::Key("missing key name in BIND key file".to_string()))?;
    let algorithm =
        algorithm.ok_or_else(|| Error::Key("missing algorithm in BIND key file".to_string()))?;
    let secret_b64 =
        secret.ok_or_else(|| Error::Key("missing secret in BIND key file".to_string()))?;

    let secret_bytes = BASE64
        .decode(&secret_b64)
        .map_err(|e| Error::Key(format!("invalid base64 in key secret: {e}")))?;

    Ok(ParsedBindKey {
        tsig_name: name,
        algorithm,
        secret: secret_bytes,
    })
}

// -- Encryption --

/// Encrypt secret bytes, returning base64-encoded blob (salt + nonce + ciphertext).
fn encrypt_secret(secret: &[u8], password: &str) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Key(format!("cipher error: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, secret)
        .map_err(|e| Error::Key(format!("encryption failed: {e}")))?;

    let mut packed = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    packed.extend_from_slice(&salt);
    packed.extend_from_slice(&nonce_bytes);
    packed.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&packed))
}

/// Decrypt secret bytes from base64-encoded blob.
fn decrypt_secret(data: &str, password: &str) -> Result<Vec<u8>> {
    let packed = BASE64
        .decode(data)
        .map_err(|e| Error::Key(format!("invalid base64: {e}")))?;

    if packed.len() < SALT_LEN + NONCE_LEN + 1 {
        return Err(Error::Key("encrypted data too short".to_string()));
    }

    let salt = &packed[..SALT_LEN];
    let nonce_bytes = &packed[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &packed[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| Error::Key(format!("cipher error: {e}")))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::Key("decryption failed (wrong password?)".to_string()))
}

/// Derive a 256-bit key from a password using Argon2id.
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| Error::Key(format!("key derivation failed: {e}")))?;
    Ok(key)
}
