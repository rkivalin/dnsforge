use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{RData, RecordType};

use crate::dns::record::{Change, KeepRule, Record, is_filtered_type};

/// Compute the changeset needed to go from `current` to `desired` records.
///
/// Records matching `keeps` rules (name + type) are never deleted.
/// DNSSEC infrastructure records are always skipped.
/// SOA records are compared ignoring the serial number.
pub fn compute_changes(
    desired: &[Record],
    current: &[Record],
    keeps: &[KeepRule],
) -> Vec<Change> {
    let mut changes = Vec::new();

    // Handle SOA separately: compare all fields except serial
    if let (Some(desired_soa), Some(current_soa)) = (
        desired.iter().find(|r| r.rtype == RecordType::SOA),
        current.iter().find(|r| r.rtype == RecordType::SOA),
    )
        && soa_fields_differ(desired_soa, current_soa)
    {
            // Build the update SOA with the current serial
            let mut updated = desired_soa.clone();
            if let (RData::SOA(desired_data), RData::SOA(current_data)) =
                (&desired_soa.rdata, &current_soa.rdata)
            {
                updated.rdata = RData::SOA(SOA::new(
                    desired_data.mname().clone(),
                    desired_data.rname().clone(),
                    current_data.serial(),
                    desired_data.refresh(),
                    desired_data.retry(),
                    desired_data.expire(),
                    desired_data.minimum(),
                ));
                updated.ttl = desired_soa.ttl;
            }
            changes.push(Change::Delete(current_soa.clone()));
            changes.push(Change::Add(updated));
    }

    // Records to delete: in current but not in desired, and not kept
    for record in current {
        if is_filtered_type(record.rtype) || record.rtype == RecordType::SOA {
            continue;
        }
        if is_kept(record, keeps) {
            continue;
        }
        if !desired.contains(record) {
            changes.push(Change::Delete(record.clone()));
        }
    }

    // Records to add: in desired but not in current
    for record in desired {
        if record.rtype == RecordType::SOA {
            continue;
        }
        if !current.contains(record) {
            changes.push(Change::Add(record.clone()));
        }
    }

    changes
}

/// Compare two SOA records ignoring the serial number.
fn soa_fields_differ(desired: &Record, current: &Record) -> bool {
    if let (RData::SOA(d), RData::SOA(c)) = (&desired.rdata, &current.rdata) {
        d.mname() != c.mname()
            || d.rname() != c.rname()
            || d.refresh() != c.refresh()
            || d.retry() != c.retry()
            || d.expire() != c.expire()
            || d.minimum() != c.minimum()
            || desired.ttl != current.ttl
    } else {
        false
    }
}

/// Check if a record matches any keep rule.
fn is_kept(record: &Record, keeps: &[KeepRule]) -> bool {
    keeps.iter().any(|k| {
        record.name.eq_ignore_ascii_case(&k.name) && record.rtype == k.rtype
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, TXT};
    use hickory_proto::rr::Name;
    use std::net::Ipv4Addr;

    fn a_rec(name: &str, ttl: u32, ip: &str) -> Record {
        let addr: Ipv4Addr = ip.parse().unwrap();
        Record {
            name: name.to_string(),
            ttl,
            rtype: RecordType::A,
            rdata: RData::A(A(addr)),
        }
    }

    fn soa_rec(name: &str, ttl: u32, serial: u32, minimum: u32) -> Record {
        Record {
            name: name.to_string(),
            ttl,
            rtype: RecordType::SOA,
            rdata: RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com.").unwrap(),
                Name::from_ascii("admin.example.com.").unwrap(),
                serial,
                3600,
                900,
                604800,
                minimum,
            )),
        }
    }

    #[test]
    fn test_no_changes() {
        let records = vec![a_rec("www.example.com.", 3600, "1.2.3.4")];
        let changes = compute_changes(&records, &records, &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_add_record() {
        let desired = vec![a_rec("www.example.com.", 3600, "1.2.3.4")];
        let current = vec![];
        let changes = compute_changes(&desired, &current, &[]);
        assert_eq!(changes.len(), 1);
        assert!(changes[0].is_add());
    }

    #[test]
    fn test_delete_record() {
        let desired = vec![];
        let current = vec![a_rec("old.example.com.", 3600, "5.6.7.8")];
        let changes = compute_changes(&desired, &current, &[]);
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].is_add());
    }

    #[test]
    fn test_keep_rule_prevents_deletion() {
        let desired = vec![];
        let current = vec![a_rec("pf.example.com.", 3600, "10.0.0.1")];
        let keeps = vec![KeepRule {
            name: "pf.example.com.".to_string(),
            rtype: RecordType::A,
        }];
        let changes = compute_changes(&desired, &current, &keeps);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_ttl_change_causes_update() {
        let desired = vec![a_rec("www.example.com.", 7200, "1.2.3.4")];
        let current = vec![a_rec("www.example.com.", 3600, "1.2.3.4")];
        let changes = compute_changes(&desired, &current, &[]);
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn test_txt_comparison() {
        let desired = vec![Record {
            name: "example.com.".to_string(),
            ttl: 3600,
            rtype: RecordType::TXT,
            rdata: RData::TXT(TXT::new(vec!["v=spf1 mx ~all".to_string()])),
        }];
        let current = desired.clone();
        let changes = compute_changes(&desired, &current, &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_txt_multi_string_comparison() {
        let desired = vec![Record {
            name: "example.com.".to_string(),
            ttl: 3600,
            rtype: RecordType::TXT,
            rdata: RData::TXT(TXT::new(vec!["part1".to_string(), "part2".to_string()])),
        }];
        let current = desired.clone();
        let changes = compute_changes(&desired, &current, &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_soa_serial_ignored() {
        let desired = vec![soa_rec("example.com.", 86400, 0, 3600)];
        let current = vec![soa_rec("example.com.", 86400, 12345, 3600)];
        let changes = compute_changes(&desired, &current, &[]);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_soa_field_change_detected() {
        let desired = vec![soa_rec("example.com.", 86400, 0, 7200)];
        let current = vec![soa_rec("example.com.", 86400, 12345, 3600)];
        let changes = compute_changes(&desired, &current, &[]);
        assert_eq!(changes.len(), 2); // delete old + add new

        // The added SOA should have the current serial (12345), not 0
        let added = changes.iter().find(|c| c.is_add()).unwrap();
        if let Change::Add(rec) = added {
            if let RData::SOA(soa) = &rec.rdata {
                assert_eq!(soa.serial(), 12345);
                assert_eq!(soa.minimum(), 7200);
            } else {
                panic!("expected SOA");
            }
        }
    }

    #[test]
    fn test_soa_ttl_change_detected() {
        let desired = vec![soa_rec("example.com.", 43200, 0, 3600)];
        let current = vec![soa_rec("example.com.", 86400, 100, 3600)];
        let changes = compute_changes(&desired, &current, &[]);
        assert_eq!(changes.len(), 2);
    }
}
