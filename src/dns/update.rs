use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_client::client::Client;
use hickory_proto::op::{Message, MessageType, OpCode, MessageFinalizer, Query, ResponseCode, UpdateMessage};
use hickory_proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::xfer::{DnsHandle, DnsResponse};

use crate::dns::record::Change;
use crate::error::{Error, Result};

/// Apply a set of changes to a DNS zone via RFC 2136 dynamic update.
pub async fn apply_changes(
    server_addr: SocketAddr,
    zone: &str,
    changes: &[Change],
    signer: Arc<dyn MessageFinalizer>,
) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }

    let timeout = Duration::from_secs(30);

    let (stream, sender) =
        TcpClientStream::new::<hickory_proto::runtime::TokioRuntimeProvider>(
            server_addr,
            None,
            Some(timeout),
            Default::default(),
        );

    let (client, bg) = Client::with_timeout(stream, sender, timeout, Some(signer))
        .await
        .map_err(|e| Error::Dns(format!("update connection to {server_addr} failed: {e}")))?;

    let bg_handle = tokio::spawn(async move {
        let _ = bg.await;
    });

    let zone_name = Name::from_ascii(zone)
        .map_err(|e| Error::Dns(format!("invalid zone name '{zone}': {e}")))?;

    // Build a single RFC 2136 update message with all changes
    let mut message = Message::new();
    message
        .set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Update)
        .set_recursion_desired(false);

    let mut zone_query = Query::new();
    zone_query
        .set_name(zone_name.clone())
        .set_query_class(DNSClass::IN)
        .set_query_type(RecordType::SOA);
    message.add_zone(zone_query);

    for change in changes {
        match change {
            Change::Delete(rec) => {
                let name = Name::from_ascii(&rec.name)
                    .map_err(|e| Error::Dns(format!("invalid record name '{}': {e}", rec.name)))?;
                let mut record = Record::from_rdata(name, 0, rec.rdata.clone());
                record.set_dns_class(DNSClass::NONE);
                message.add_update(record);
            }
            Change::Add(rec) => {
                let name = Name::from_ascii(&rec.name)
                    .map_err(|e| Error::Dns(format!("invalid record name '{}': {e}", rec.name)))?;
                let record = Record::from_rdata(name, rec.ttl, rec.rdata.clone());
                message.add_update(record);
            }
        }
    }

    // Send the update
    use futures_core::Stream;
    use std::pin::Pin;
    use std::task::Poll;
    let mut stream = client.send(message);
    let response = std::future::poll_fn(|cx| -> Poll<Option<_>> { Pin::new(&mut stream).poll_next(cx) })
        .await
        .ok_or_else(|| Error::Dns("DNS update: no response".into()))?
        .map_err(|e| Error::Dns(format!("DNS update failed: {e}")))?;

    check_update_response(&response)?;

    bg_handle.abort();
    Ok(())
}

/// Check the DNS response code from an update operation.
fn check_update_response(response: &DnsResponse) -> Result<()> {
    let code = response.response_code();
    match code {
        ResponseCode::NoError => Ok(()),
        ResponseCode::Refused => Err(Error::Dns(
            "update REFUSED by server (check TSIG key and update-policy)".into(),
        )),
        ResponseCode::NotAuth => Err(Error::Dns(
            "server is not authoritative for this zone (NOTAUTH)".into(),
        )),
        ResponseCode::NotZone => Err(Error::Dns(
            "update name is not within the zone (NOTZONE)".into(),
        )),
        _ => Err(Error::Dns(format!(
            "server responded with {code}"
        ))),
    }
}
