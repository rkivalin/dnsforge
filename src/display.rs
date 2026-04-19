use std::io::{self, Write};

use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};

use crate::dns::record::{Change, ZoneDefinition, format_rdata};

/// Max column width to consider when computing padding.
/// Values longer than this are not used to determine column width.
const MAX_NAME_WIDTH: usize = 40;

/// Display changes for a zone with colored, column-aligned output.
pub fn print_zone_changes(
    zone: &ZoneDefinition,
    changes: &[Change],
    use_color: bool,
) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    // Zone header
    if use_color {
        write!(stdout, "{}", SetAttribute(Attribute::Bold))?;
    }
    write!(stdout, "{}", zone.label())?;
    if use_color {
        write!(stdout, "{}", SetAttribute(Attribute::Reset))?;
    }
    writeln!(stdout, " ({}):", zone.key_name)?;

    if changes.is_empty() {
        return Ok(());
    }

    // Pre-compute column values for each row
    let rows: Vec<Row> = changes
        .iter()
        .map(|change| {
            let rec = match change {
                Change::Add(r) | Change::Delete(r) => r,
            };
            Row {
                sign: if change.is_add() { '+' } else { '-' },
                name: rec.name.clone(),
                ttl: rec.ttl.to_string(),
                rtype: rec.rtype.to_string(),
                rdata: format_rdata(&rec.rdata),
                is_add: change.is_add(),
            }
        })
        .collect();

    // Compute column widths (ignoring outliers)
    let name_w = column_width(rows.iter().map(|r| r.name.len()), MAX_NAME_WIDTH);
    let ttl_w = column_width(rows.iter().map(|r| r.ttl.len()), 10);
    let rtype_w = column_width(rows.iter().map(|r| r.rtype.len()), 10);

    for row in &rows {
        let color = if row.is_add { Color::Green } else { Color::Red };

        if use_color {
            write!(stdout, "{}", SetForegroundColor(color))?;
        }
        write!(
            stdout,
            "  {} {:<name_w$} {:>ttl_w$} IN {:<rtype_w$} {}",
            row.sign, row.name, row.ttl, row.rtype, row.rdata,
        )?;
        if use_color {
            write!(stdout, "{}", ResetColor)?;
        }
        writeln!(stdout)?;
    }

    writeln!(stdout)?;
    Ok(())
}

struct Row {
    sign: char,
    name: String,
    ttl: String,
    rtype: String,
    rdata: String,
    is_add: bool,
}

/// Compute column width from an iterator of lengths, ignoring values above max.
fn column_width(lengths: impl Iterator<Item = usize>, max: usize) -> usize {
    lengths.filter(|&l| l <= max).max().unwrap_or(0)
}

/// Print a summary of all changes across zones.
pub fn print_summary(total_additions: usize, total_deletions: usize, use_color: bool) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    if total_additions == 0 && total_deletions == 0 {
        writeln!(stdout, "No changes.")?;
        return Ok(());
    }

    let total = total_additions + total_deletions;
    write!(stdout, "{total} change{}", if total == 1 { "" } else { "s" })?;
    write!(stdout, " (")?;

    if total_additions > 0 {
        if use_color {
            write!(stdout, "{}", SetForegroundColor(Color::Green))?;
        }
        write!(stdout, "{total_additions} addition{}", if total_additions == 1 { "" } else { "s" })?;
        if use_color {
            write!(stdout, "{}", ResetColor)?;
        }
    }
    if total_additions > 0 && total_deletions > 0 {
        write!(stdout, ", ")?;
    }
    if total_deletions > 0 {
        if use_color {
            write!(stdout, "{}", SetForegroundColor(Color::Red))?;
        }
        write!(stdout, "{total_deletions} deletion{}", if total_deletions == 1 { "" } else { "s" })?;
        if use_color {
            write!(stdout, "{}", ResetColor)?;
        }
    }
    writeln!(stdout, ")")?;

    Ok(())
}

/// Determine whether to use color based on CLI flag and terminal detection.
pub fn should_use_color(mode: &crate::cli::ColorMode) -> bool {
    match mode {
        crate::cli::ColorMode::Always => true,
        crate::cli::ColorMode::Never => false,
        crate::cli::ColorMode::Auto => crossterm::tty::IsTty::is_tty(&io::stdout()),
    }
}
