use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_client::client::{Client, ClientHandle};
use hickory_proto::op::{MessageFinalizer, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::tcp::TcpClientStream;

use crate::dns::record::{Record, is_filtered_type};
use crate::error::{Error, Result};

/// Perform an AXFR zone transfer and return all records (filtered of DNSSEC types).
pub async fn fetch_zone(
    server_addr: SocketAddr,
    zone: &str,
    signer: Arc<dyn MessageFinalizer>,
) -> Result<Vec<Record>> {
    let timeout = Duration::from_secs(30);

    let (stream, sender) =
        TcpClientStream::new::<hickory_proto::runtime::TokioRuntimeProvider>(
            server_addr,
            None,
            Some(timeout),
            Default::default(),
        );

    let (mut client, bg) = Client::with_timeout(stream, sender, timeout, Some(signer))
        .await
        .map_err(|e| Error::Dns(format!("AXFR connection to {server_addr} failed: {e}")))?;

    let bg_handle = tokio::spawn(async move {
        let _ = bg.await;
    });

    let zone_name = Name::from_ascii(zone)
        .map_err(|e| Error::Dns(format!("invalid zone name '{zone}': {e}")))?;

    let response = client
        .query(zone_name.clone(), DNSClass::IN, RecordType::AXFR)
        .await
        .map_err(|e| Error::Dns(format!("AXFR query for {zone} failed: {e}")))?;

    // Check response code
    let rcode = response.response_code();
    if rcode != ResponseCode::NoError {
        return Err(Error::Dns(format!(
            "AXFR for {zone} failed: server responded with {rcode}"
        )));
    }

    let answers: Vec<_> = response.answers().to_vec();

    // An AXFR response must contain at least the SOA record
    let has_soa = answers.iter().any(|rr| rr.record_type() == RecordType::SOA);
    if !has_soa {
        return Err(Error::Dns(format!(
            "AXFR for {zone} returned no SOA record (zone transfer may have been denied)"
        )));
    }

    let mut records = Vec::new();

    for rr in &answers {
        let rtype = rr.record_type();

        if is_filtered_type(rtype) {
            continue;
        }

        let name = rr.name().to_string();
        let ttl = rr.ttl();
        let rdata = rr.data().clone();

        records.push(Record {
            name,
            ttl,
            rtype,
            rdata,
        });
    }

    bg_handle.abort();

    Ok(records)
}
