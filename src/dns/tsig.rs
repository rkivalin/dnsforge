use std::sync::Arc;

use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::op::{Message, MessageFinalizer, MessageVerifier};
use hickory_proto::rr::{Name, Record};
use hickory_proto::ProtoError;

use crate::error::{Error, Result};
use crate::keystore::TsigKey;

/// Wrapper around TSigner that signs all messages, not just updates.
///
/// The default TSigner only signs Update/Notify/AXFR/IXFR messages. This wrapper
/// overrides `should_finalize_message` to always return true, so regular queries
/// are also TSIG-signed. This is needed when the DNS server uses TSIG keys for
/// view selection.
struct AlwaysSignTsig(TSigner);

impl MessageFinalizer for AlwaysSignTsig {
    fn finalize_message(
        &self,
        message: &Message,
        current_time: u32,
    ) -> std::result::Result<(Vec<Record>, Option<MessageVerifier>), ProtoError> {
        self.0.finalize_message(message, current_time)
    }

    fn should_finalize_message(&self, _message: &Message) -> bool {
        true
    }
}

/// Create a TSIG signer from a loaded key.
pub fn create_signer(key: &TsigKey) -> Result<Arc<dyn MessageFinalizer>> {
    let algorithm = match key.algorithm.to_lowercase().as_str() {
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        other => {
            return Err(Error::Dns(format!("unsupported TSIG algorithm: {other}")));
        }
    };

    let signer_name = Name::from_ascii(&key.tsig_name)
        .map_err(|e| Error::Dns(format!("invalid TSIG key name '{}': {e}", key.tsig_name)))?;

    let signer = TSigner::new(key.secret.clone(), algorithm, signer_name, 300)
        .map_err(|e| Error::Dns(format!("failed to create TSIG signer: {e}")))?;

    Ok(Arc::new(AlwaysSignTsig(signer)))
}
