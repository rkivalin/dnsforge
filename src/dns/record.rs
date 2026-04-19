use std::fmt;

use hickory_proto::rr::{RData, RecordType};

/// A normalized DNS record for comparison and display.
///
/// Uses hickory's `RData` directly to avoid lossy string round-tripping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Fully qualified domain name (e.g. "www.example.com.")
    pub name: String,
    /// TTL in seconds
    pub ttl: u32,
    /// Record type
    pub rtype: RecordType,
    /// Record data (structured, not string)
    pub rdata: RData,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} IN {} {}",
            self.name,
            self.ttl,
            self.rtype,
            format_rdata(&self.rdata)
        )
    }
}

/// Format RData for human-readable display.
///
/// TXT records need special handling: hickory's Display concatenates all strings
/// without quotes, but we want `"string1" "string2"` format.
pub fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::TXT(txt) => txt
            .iter()
            .map(|s| format!("\"{}\"", String::from_utf8_lossy(s)))
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}

/// Rule to keep externally managed records (don't delete them).
#[derive(Debug, Clone)]
pub struct KeepRule {
    /// Fully qualified name
    pub name: String,
    /// Record type
    pub rtype: RecordType,
}

/// A change to apply to a DNS zone.
#[derive(Debug, Clone)]
pub enum Change {
    Add(Record),
    Delete(Record),
}

impl Change {
    pub fn is_add(&self) -> bool {
        matches!(self, Change::Add(_))
    }
}

/// Information about a zone collected from script evaluation.
#[derive(Debug, Clone)]
pub struct ZoneDefinition {
    /// DNS server address
    pub server: String,
    /// Zone domain (e.g. "example.com")
    pub domain: String,
    /// TSIG key name (references keystore)
    pub key_name: String,
    /// Optional view name (for split-horizon DNS)
    pub view: Option<String>,
    /// Desired records
    pub records: Vec<Record>,
    /// Rules for records to keep as-is
    pub keeps: Vec<KeepRule>,
}

impl ZoneDefinition {
    /// Display label for this zone (used in output headers).
    pub fn label(&self) -> String {
        match &self.view {
            Some(view) => format!("{}/{}", self.domain, view),
            None => self.domain.clone(),
        }
    }
}

/// Record types that should be filtered from AXFR results (DNSSEC infrastructure).
const FILTERED_TYPES: &[RecordType] = &[
    RecordType::RRSIG,
    RecordType::NSEC,
    RecordType::NSEC3,
    RecordType::NSEC3PARAM,
    RecordType::DNSKEY,
    RecordType::CDS,
    RecordType::CDNSKEY,
];

/// Check if a record type should be filtered from AXFR results.
pub fn is_filtered_type(rtype: RecordType) -> bool {
    FILTERED_TYPES.contains(&rtype)
        || matches!(rtype, RecordType::Unknown(..))
}

/// Normalize a record name: lowercase, ensure trailing dot.
pub fn normalize_name(name: &str, zone: &str) -> String {
    let name = name.to_ascii_lowercase();
    let zone = zone.to_ascii_lowercase();
    let zone_dot = if zone.ends_with('.') {
        zone.clone()
    } else {
        format!("{zone}.")
    };

    if name == "@" {
        zone_dot
    } else if name.ends_with('.') {
        name
    } else {
        format!("{name}.{zone_dot}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_name() {
        assert_eq!(normalize_name("@", "example.com"), "example.com.");
        assert_eq!(normalize_name("www", "example.com"), "www.example.com.");
        assert_eq!(normalize_name("www", "example.com."), "www.example.com.");
        assert_eq!(normalize_name("mail.example.com.", "example.com"), "mail.example.com.");
        assert_eq!(normalize_name("WWW", "EXAMPLE.COM"), "www.example.com.");
    }

    #[test]
    fn test_format_rdata_txt_single() {
        use hickory_proto::rr::rdata::TXT;
        let txt = RData::TXT(TXT::new(vec!["v=spf1 mx ~all".to_string()]));
        assert_eq!(format_rdata(&txt), r#""v=spf1 mx ~all""#);
    }

    #[test]
    fn test_format_rdata_txt_multi() {
        use hickory_proto::rr::rdata::TXT;
        let txt = RData::TXT(TXT::new(vec![
            "v=DKIM1; k=rsa; ".to_string(),
            "p=MII...".to_string(),
        ]));
        assert_eq!(format_rdata(&txt), r#""v=DKIM1; k=rsa; " "p=MII...""#);
    }
}
