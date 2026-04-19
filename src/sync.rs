use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

use hickory_proto::op::MessageFinalizer;

use crate::diff;
use crate::display;
use crate::dns::{axfr, tsig, update};
use crate::dns::record::{Change, ZoneDefinition};
use crate::error::{Error, Result};
use crate::keystore;

/// Result of synchronizing a single zone.
struct ZoneSyncResult {
    zone: ZoneDefinition,
    changes: Vec<Change>,
}

/// Run the full sync pipeline: evaluate scripts, AXFR, diff, display, optionally apply.
/// Returns true if there were changes (for exit code in dry-run mode).
pub async fn run(
    files: &[impl AsRef<Path>],
    dry_run: bool,
    no_confirm: bool,
    zone_filter: &[String],
    use_color: bool,
) -> Result<bool> {
    // 1. Evaluate all zone files
    let mut all_zones = Vec::new();
    for file in files {
        let file = file.as_ref();
        tracing::info!("evaluating {}", file.display());
        let zones = crate::script::evaluate_file(file)?;
        all_zones.extend(zones);
    }

    // Apply zone filter if specified
    if !zone_filter.is_empty() {
        all_zones.retain(|z| {
            zone_filter.iter().any(|f| {
                z.domain.eq_ignore_ascii_case(f)
                    || z.label().eq_ignore_ascii_case(f)
            })
        });
        if all_zones.is_empty() {
            return Err(Error::Config("no zones matched the --zone filter".into()));
        }
    }

    // 2. Load TSIG keys (deduplicated by key name)
    let mut pw_cache = keystore::PasswordCache::new();
    let mut signers: HashMap<String, Arc<dyn MessageFinalizer>> = HashMap::new();
    for zone in &all_zones {
        if !signers.contains_key(&zone.key_name) {
            tracing::debug!("loading TSIG key '{}'", zone.key_name);
            let key = keystore::load_key(&zone.key_name, &mut pw_cache)?;
            let signer = tsig::create_signer(&key)?;
            signers.insert(zone.key_name.clone(), signer);
        }
    }

    // 3. For each zone: AXFR, diff, collect results
    let mut results = Vec::new();
    for zone in all_zones {
        let server_addr = resolve_server(&zone.server)?;
        let signer = signers[&zone.key_name].clone();

        tracing::info!("fetching zone {} from {}", zone.label(), zone.server);
        let current_records = axfr::fetch_zone(server_addr, &zone.domain, signer).await?;

        tracing::debug!(
            "zone {} has {} current records, {} desired records",
            zone.label(),
            current_records.len(),
            zone.records.len()
        );

        let changes = diff::compute_changes(&zone.records, &current_records, &zone.keeps);

        results.push(ZoneSyncResult { zone, changes });
    }

    // 4. Display changes
    let mut total_additions = 0;
    let mut total_deletions = 0;

    for result in &results {
        if result.changes.is_empty() {
            continue;
        }
        display::print_zone_changes(&result.zone, &result.changes, use_color)?;
        for change in &result.changes {
            if change.is_add() {
                total_additions += 1;
            } else {
                total_deletions += 1;
            }
        }
    }

    display::print_summary(total_additions, total_deletions, use_color)?;

    let has_changes = total_additions > 0 || total_deletions > 0;

    if !has_changes || dry_run {
        return Ok(has_changes);
    }

    // 5. Confirm and apply
    if !no_confirm {
        eprint!("\nApply changes? [y/N] ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(has_changes);
        }
    }

    for result in &results {
        if result.changes.is_empty() {
            continue;
        }

        let server_addr = resolve_server(&result.zone.server)?;
        let signer = signers[&result.zone.key_name].clone();

        tracing::info!("applying {} changes to {}", result.changes.len(), result.zone.label());
        update::apply_changes(server_addr, &result.zone.domain, &result.changes, signer).await?;
    }

    eprintln!("Done.");
    Ok(has_changes)
}

/// Validate zone files without connecting to DNS.
pub fn check(files: &[impl AsRef<Path>]) -> Result<()> {
    for file in files {
        let file = file.as_ref();
        let zones = crate::script::evaluate_file(file)?;
        eprintln!(
            "{}: {} zone{}",
            file.display(),
            zones.len(),
            if zones.len() == 1 { "" } else { "s" }
        );
        for zone in &zones {
            eprintln!(
                "  {} ({}, {} records, {} keep rules)",
                zone.label(),
                zone.key_name,
                zone.records.len(),
                zone.keeps.len()
            );
        }
    }
    Ok(())
}

/// Resolve a server address string to a SocketAddr (defaulting to port 53).
fn resolve_server(server: &str) -> Result<SocketAddr> {
    let addr_str = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:53")
    };

    addr_str
        .to_socket_addrs()
        .map_err(|e| Error::Dns(format!("failed to resolve DNS server '{server}': {e}")))?
        .next()
        .ok_or_else(|| Error::Dns(format!("DNS server '{server}' resolved to no addresses")))
}
