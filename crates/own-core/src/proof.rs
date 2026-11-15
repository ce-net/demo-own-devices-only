//! Holder proof: the exact bytes a device signs for one request.
//!
//! The gate never trusts a claimed sender. It takes the chain's leaf audience (the key the chain
//! was issued to) and checks the request signature under that key. A copied key file signed by any
//! other device fails here.

use serde::{Deserialize, Serialize};

/// The domain tag of a call to access.gate.
pub const CALL_DOMAIN: &str = "ce-own-devices-call-v1";
/// The domain tag of a revoke request to revoke.list.
pub const REVOKE_DOMAIN: &str = "ce-own-devices-revoke-v1";
/// The domain tag of a pairing-code request from the owner to device.enroll.
pub const PAIR_DOMAIN: &str = "ce-own-devices-pair-v1";
/// The domain tag of a device's enrollment (proof that it holds the key it asks a chain for).
pub const ENROLL_DOMAIN: &str = "ce-own-devices-enroll-v1";
/// The domain tag of a signed revocation-list snapshot.
pub const LIST_DOMAIN: &str = "ce-own-devices-revlist-v1";

/// How far a request's timestamp may be from the receiver's clock.
pub const MAX_SKEW_MS: u64 = 30_000;

/// A signed request envelope (gate calls and revoke requests).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signed {
    /// The holder-bound chain, hex.
    pub chain: String,
    /// Sender's clock, unix ms.
    pub ts: u64,
    /// Random per request; the receiver refuses a nonce it has seen.
    pub nonce: u64,
    /// What is asked: for the gate `METHOD /path`, for revoke.list the target (see `revoke_subject`).
    pub what: String,
    /// The request body (the gate forwards it upstream).
    #[serde(default)]
    pub body: String,
    /// Ed25519 signature by the chain's holder over [`message`], hex.
    pub sig: String,
}

/// The bytes signed for a request to `receiver` (the receiving cell's key, hex).
pub fn message(domain: &str, receiver_hex: &str, chain_hex: &str, ts: u64, nonce: u64, what: &str, body: &str) -> Vec<u8> {
    format!(
        "{domain}\nto {receiver_hex}\nchain {}\nts {ts}\nnonce {nonce}\nwhat {what}\nbody {}\n",
        crate::sha256_hex(chain_hex.trim().as_bytes()),
        crate::sha256_hex(body.as_bytes())
    )
    .into_bytes()
}

/// Build and sign an envelope.
pub fn sign(
    id: &ce_net_proto::Identity,
    domain: &str,
    receiver_hex: &str,
    chain_hex: &str,
    what: &str,
    body: &str,
) -> Signed {
    let ts = crate::now_ms();
    let nonce = crate::keys::random_u64();
    let m = message(domain, receiver_hex, chain_hex, ts, nonce, what, body);
    Signed {
        chain: chain_hex.trim().to_string(),
        ts,
        nonce,
        what: what.to_string(),
        body: body.to_string(),
        sig: hex::encode(id.sign(&m)),
    }
}

/// Is `s` signed by `holder` for `receiver`? Returns the reason when not.
pub fn check(domain: &str, receiver_hex: &str, holder: &ce_net_proto::NodeId, s: &Signed) -> Result<(), String> {
    let sig: [u8; 64] = hex::decode(&s.sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("holder proof does not match: the signature is not 64 hex bytes")?;
    let m = message(domain, receiver_hex, &s.chain, s.ts, s.nonce, &s.what, &s.body);
    ce_net_proto::identity::verify(holder, &m, &sig).map_err(|_| {
        format!(
            "holder proof does not match: the request is not signed by the chain's holder {}",
            &hex::encode(holder)[..16]
        )
    })
}

/// Everything a receiving cell checks on a signed request, in order:
/// the chain decodes; the request is signed by the chain's leaf holder (holder proof); the
/// timestamp is fresh; then ce-net-proto's `authorize`: rooted at `owner`, every signature, expiry,
/// revocation, resource `Tag(GROUP_TAG)` matches this cell, each link inside its parent, and the
/// leaf grants `action`. Returns the holder key.
pub fn authorize(
    domain: &str,
    self_id: &ce_net_proto::NodeId,
    owner: &ce_net_proto::NodeId,
    s: &Signed,
    action: &str,
    now_ms: u64,
    is_revoked: &dyn Fn(&ce_net_proto::NodeId, u64) -> bool,
) -> Result<ce_net_proto::NodeId, String> {
    let chain = ce_net_proto::decode_chain(&s.chain).map_err(|e| e.0)?;
    let holder = chain.last().ok_or("no capability presented")?.cap.audience;
    check(domain, &hex::encode(self_id), &holder, s)?;
    if s.ts.abs_diff(now_ms) > MAX_SKEW_MS {
        return Err("request timestamp is too far from this cell's clock".into());
    }
    ce_net_proto::authorize(
        self_id,
        &[*owner],
        &[crate::GROUP_TAG.to_string()],
        now_ms / 1000,
        &holder,
        action,
        &chain,
        is_revoked,
    )?;
    Ok(holder)
}

/// Remembers request nonces for twice the allowed skew, so a captured request cannot be replayed.
#[derive(Default)]
pub struct Replay(std::sync::Mutex<std::collections::HashMap<(ce_net_proto::NodeId, u64), u64>>);

impl Replay {
    /// `Err` when `(holder, nonce)` was seen before.
    pub fn first_use(&self, holder: &ce_net_proto::NodeId, nonce: u64, now_ms: u64) -> Result<(), String> {
        let mut m = self.0.lock().unwrap();
        m.retain(|_, t| now_ms.saturating_sub(*t) < 2 * MAX_SKEW_MS);
        if m.insert((*holder, nonce), now_ms).is_some() {
            return Err("replayed request (nonce already used)".into());
        }
        Ok(())
    }
}
