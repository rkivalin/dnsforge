use std::cell::RefCell;
use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hickory_proto::rr::rdata::*;
use hickory_proto::rr::{Name, RData, RecordType};
use rhai::{Dynamic, Engine, EvalAltResult, Map};

use crate::dns::record::{KeepRule, Record, ZoneDefinition, normalize_name};

/// Mutable state accumulated during script evaluation.
#[derive(Debug, Default)]
pub struct ScriptState {
    /// Current DNS server address.
    server: Option<String>,
    /// Current default TTL.
    ttl: u32,
    /// Zones defined so far, with the last one being the "active" zone.
    zones: Vec<ZoneDefinition>,
}

impl ScriptState {
    fn current_zone_mut(&mut self) -> std::result::Result<&mut ZoneDefinition, Box<EvalAltResult>> {
        self.zones
            .last_mut()
            .ok_or_else(|| "no zone defined yet; call zone() first".into())
    }

    fn current_domain(&self) -> std::result::Result<&str, Box<EvalAltResult>> {
        self.zones
            .last()
            .map(|z| z.domain.as_str())
            .ok_or_else(|| "no zone defined yet; call zone() first".into())
    }

    fn add_record(
        &mut self,
        name: &str,
        rtype: RecordType,
        rdata: RData,
    ) -> std::result::Result<(), Box<EvalAltResult>> {
        let domain = self.current_domain()?.to_owned();
        let fqdn = normalize_name(name, &domain);
        let ttl = self.ttl;
        let zone = self.current_zone_mut()?;
        zone.records.push(Record {
            name: fqdn,
            ttl,
            rtype,
            rdata,
        });
        Ok(())
    }

    /// Consume state into final zone definitions.
    pub fn into_zones(self) -> Vec<ZoneDefinition> {
        self.zones
    }
}

type SharedState = Rc<RefCell<ScriptState>>;

fn parse_name(s: &str) -> std::result::Result<Name, Box<EvalAltResult>> {
    Name::from_ascii(s).map_err(|e| format!("invalid DNS name '{s}': {e}").into())
}

/// Register all DNS built-in functions on the Rhai engine.
pub fn register_builtins(engine: &mut Engine, state: SharedState) {
    // server(address)
    {
        let st = state.clone();
        engine.register_fn("server", move |addr: &str| {
            st.borrow_mut().server = Some(addr.to_string());
        });
    }

    // zone(domain, key_name) and zone(domain, key_name, view)
    {
        let st = state.clone();
        engine.register_fn("zone", move |domain: &str, key_name: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let mut s = st.borrow_mut();
            let server = s.server.clone().ok_or_else(|| -> Box<EvalAltResult> {
                "no server defined; call server() before zone()".into()
            })?;
            s.ttl = 3600;
            s.zones.push(ZoneDefinition {
                server,
                domain: domain.to_string(),
                key_name: key_name.to_string(),
                view: None,
                records: Vec::new(),
                keeps: Vec::new(),
            });
            Ok(())
        });
    }
    {
        let st = state.clone();
        engine.register_fn("zone", move |domain: &str, key_name: &str, view: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let mut s = st.borrow_mut();
            let server = s.server.clone().ok_or_else(|| -> Box<EvalAltResult> {
                "no server defined; call server() before zone()".into()
            })?;
            s.ttl = 3600;
            s.zones.push(ZoneDefinition {
                server,
                domain: domain.to_string(),
                key_name: key_name.to_string(),
                view: Some(view.to_string()),
                records: Vec::new(),
                keeps: Vec::new(),
            });
            Ok(())
        });
    }

    // ttl(seconds)
    {
        let st = state.clone();
        engine.register_fn("ttl", move |seconds: i64| {
            st.borrow_mut().ttl = seconds as u32;
        });
    }

    // soa(mname, rname, params)
    {
        let st = state.clone();
        engine.register_fn("soa", move |mname: &str, rname: &str, params: Map| -> std::result::Result<(), Box<EvalAltResult>> {
            let refresh = map_int(&params, "refresh", 43200)? as u32;
            let retry = map_int(&params, "retry", 7200)? as u32;
            let expire = map_int(&params, "expire", 1209600)? as u32;
            let minimum = map_int(&params, "minimum", 3600)? as u32;
            let mname = parse_name(mname)?;
            let rname = parse_name(rname)?;
            // Serial 0 in desired state; diff engine preserves current serial
            let soa = SOA::new(mname, rname, 0, refresh as i32, retry as i32, expire as i32, minimum);
            st.borrow_mut().add_record("@", RecordType::SOA, RData::SOA(soa))
        });
    }

    // a(name, ip)
    {
        let st = state.clone();
        engine.register_fn("a", move |name: &str, ip: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let addr = ip.parse().map_err(|e| -> Box<EvalAltResult> { format!("invalid IPv4 address '{ip}': {e}").into() })?;
            st.borrow_mut().add_record(name, RecordType::A, RData::A(A(addr)))
        });
    }

    // aaaa(name, ip6)
    {
        let st = state.clone();
        engine.register_fn("aaaa", move |name: &str, ip6: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let addr = ip6.parse().map_err(|e| -> Box<EvalAltResult> { format!("invalid IPv6 address '{ip6}': {e}").into() })?;
            st.borrow_mut().add_record(name, RecordType::AAAA, RData::AAAA(AAAA(addr)))
        });
    }

    // ns(target) - defaults name to @
    {
        let st = state.clone();
        engine.register_fn("ns", move |target: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let name = parse_name(target)?;
            st.borrow_mut().add_record("@", RecordType::NS, RData::NS(NS(name)))
        });
    }

    // ns(name, target)
    {
        let st = state.clone();
        engine.register_fn("ns", move |name: &str, target: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let target = parse_name(target)?;
            st.borrow_mut().add_record(name, RecordType::NS, RData::NS(NS(target)))
        });
    }

    // cname(name, target)
    {
        let st = state.clone();
        engine.register_fn("cname", move |name: &str, target: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let target = parse_name(target)?;
            st.borrow_mut().add_record(name, RecordType::CNAME, RData::CNAME(CNAME(target)))
        });
    }

    // mx(name, priority, target)
    {
        let st = state.clone();
        engine.register_fn("mx", move |name: &str, priority: i64, target: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let exchange = parse_name(target)?;
            let mx = MX::new(priority as u16, exchange);
            st.borrow_mut().add_record(name, RecordType::MX, RData::MX(mx))
        });
    }

    // txt(name, s1) .. txt(name, s1, s2, s3, s4)
    {
        let st = state.clone();
        engine.register_fn("txt", move |name: &str, s1: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let txt = TXT::new(vec![s1.to_string()]);
            st.borrow_mut().add_record(name, RecordType::TXT, RData::TXT(txt))
        });
    }
    {
        let st = state.clone();
        engine.register_fn("txt", move |name: &str, s1: &str, s2: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let txt = TXT::new(vec![s1.to_string(), s2.to_string()]);
            st.borrow_mut().add_record(name, RecordType::TXT, RData::TXT(txt))
        });
    }
    {
        let st = state.clone();
        engine.register_fn("txt", move |name: &str, s1: &str, s2: &str, s3: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let txt = TXT::new(vec![s1.to_string(), s2.to_string(), s3.to_string()]);
            st.borrow_mut().add_record(name, RecordType::TXT, RData::TXT(txt))
        });
    }
    {
        let st = state.clone();
        engine.register_fn("txt", move |name: &str, s1: &str, s2: &str, s3: &str, s4: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let txt = TXT::new(vec![s1.to_string(), s2.to_string(), s3.to_string(), s4.to_string()]);
            st.borrow_mut().add_record(name, RecordType::TXT, RData::TXT(txt))
        });
    }

    // srv(name, priority, weight, port, target)
    {
        let st = state.clone();
        engine.register_fn("srv", move |name: &str, priority: i64, weight: i64, port: i64, target: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let target = parse_name(target)?;
            let srv = SRV::new(priority as u16, weight as u16, port as u16, target);
            st.borrow_mut().add_record(name, RecordType::SRV, RData::SRV(srv))
        });
    }

    // caa(name, tag, value)
    {
        let st = state.clone();
        engine.register_fn("caa", move |name: &str, tag: &str, value: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let issuer = parse_name(value)?;
            let caa = match tag {
                "issue" => CAA::new_issue(false, Some(issuer), vec![]),
                "issuewild" => CAA::new_issuewild(false, Some(issuer), vec![]),
                _ => {
                    return Err(format!("unsupported CAA tag '{tag}'; use 'issue' or 'issuewild'").into());
                }
            };
            st.borrow_mut().add_record(name, RecordType::CAA, RData::CAA(caa))
        });
    }

    // openpgpkey(name, base64_key) - RFC 7929
    {
        let st = state.clone();
        engine.register_fn("openpgpkey", move |name: &str, key: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let stripped: String = key.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = BASE64.decode(&stripped).map_err(|e| -> Box<EvalAltResult> {
                format!("invalid base64 OPENPGPKEY data: {e}").into()
            })?;
            let pgp = OPENPGPKEY::new(bytes);
            st.borrow_mut().add_record(name, RecordType::OPENPGPKEY, RData::OPENPGPKEY(pgp))
        });
    }

    // keep(name, type) - externally managed
    {
        let st = state.clone();
        engine.register_fn("keep", move |name: &str, rtype: &str| -> std::result::Result<(), Box<EvalAltResult>> {
            let rtype: RecordType = rtype.parse().map_err(|e| -> Box<EvalAltResult> {
                format!("invalid record type '{rtype}': {e}").into()
            })?;
            let mut s = st.borrow_mut();
            let domain = s.current_domain()?.to_owned();
            let fqdn = normalize_name(name, &domain);
            let zone = s.current_zone_mut()?;
            zone.keeps.push(KeepRule { name: fqdn, rtype });
            Ok(())
        });
    }

    // env(key) - returns value or ()
    engine.register_fn("env", |key: &str| -> Dynamic {
        match std::env::var(key) {
            Ok(val) => Dynamic::from(val),
            Err(_) => Dynamic::UNIT,
        }
    });

    // env(key, default) - returns value or default
    engine.register_fn("env", |key: &str, default: &str| -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    });
}

/// Extract an integer from a Rhai map with a default value.
fn map_int(map: &Map, key: &str, default: i64) -> std::result::Result<i64, Box<EvalAltResult>> {
    match map.get(key) {
        Some(v) => v
            .as_int()
            .map_err(|_| format!("SOA parameter '{key}' must be an integer").into()),
        None => Ok(default),
    }
}
