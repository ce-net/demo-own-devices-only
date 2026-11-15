//! access.gate@1.
//!
//! Fronts one upstream. For every call, in order:
//! 1. a fresh revocation list is held (signed by the pinned revoke.list key, issued at most
//!    [`STALE_MS`] ago, version never going backwards); without one every call is refused;
//! 2. the chain decodes and the request is signed by the chain's leaf holder (holder proof);
//! 3. ce-net-proto `authorize`: rooted at the owner, signatures, expiry, revocation, the resource
//!    tag, attenuation, and the leaf grants the gate's action;
//! 4. the request nonce is new;
//! 5. only then is `METHOD /path` with the body forwarded upstream, with `X-Ce-Holder` set.

use ce_net_proto::{Identity, NodeId};
use own_core::proof::{self, CALL_DOMAIN, Replay, Signed};
use revoke_list::{Snapshot, SignedList, verify_list};
use serde_json::{Value, json};
use std::sync::Mutex;

/// A list older than this is not trusted, and the gate refuses every call until it has a newer one.
pub const STALE_MS: u64 = 3_000;
/// How often the gate fetches the list.
pub const POLL_MS: u64 = 200;

pub struct Gate {
    id: Identity,
    owner: NodeId,
    action: String,
    upstream: String,
    list_key: NodeId,
    list: Mutex<Option<Snapshot>>,
    replay: Replay,
}

pub enum Outcome {
    Allowed { holder: String, status: u16, upstream: Value },
    Refused { status: u16, reason: String },
}

impl Gate {
    pub fn new(id: Identity, owner: NodeId, action: &str, upstream: &str, list_key: NodeId) -> Self {
        Gate {
            id,
            owner,
            action: action.into(),
            upstream: upstream.trim_end_matches('/').into(),
            list_key,
            list: Mutex::new(None),
            replay: Replay::default(),
        }
    }

    pub fn id_hex(&self) -> String {
        self.id.node_id_hex()
    }

    /// Adopt a list fetched from revoke.list, if it is genuine and not older than the one held.
    pub fn adopt(&self, l: &SignedList) -> Result<(), String> {
        let snap = verify_list(l, &self.list_key)?;
        let mut cur = self.list.lock().unwrap();
        if let Some(c) = cur.as_ref() {
            if snap.version < c.version || snap.issued_ms < c.issued_ms {
                return Err("list: older than the one held".into());
            }
        }
        *cur = Some(snap);
        Ok(())
    }

    pub fn call(&self, s: &Signed, now_ms: u64) -> Outcome {
        let refuse = |status: u16, reason: String| Outcome::Refused { status, reason };
        let snap = match self.list.lock().unwrap().clone() {
            Some(x) if now_ms.saturating_sub(x.issued_ms) <= STALE_MS => x,
            Some(x) => {
                return refuse(503, format!(
                    "revocation list is {} ms old (limit {STALE_MS}); refusing every call until a fresh one arrives",
                    now_ms.saturating_sub(x.issued_ms)
                ));
            }
            None => return refuse(503, "no revocation list yet; refusing every call until one arrives".into()),
        };
        let revoked = |i: &NodeId, n: u64| {
            let iss = hex::encode(i);
            snap.entries.iter().any(|e| e.issuer == iss && e.nonce == n)
        };
        let holder = match proof::authorize(CALL_DOMAIN, &self.id.node_id(), &self.owner, s, &self.action, now_ms, &revoked) {
            Ok(h) => h,
            Err(m) => {
                let ctx = ce_net_proto::decode_chain(&s.chain).ok().and_then(|c| {
                    let h = hex::encode(c.last()?.cap.audience);
                    snap.entries.iter().find(|e| e.holder == h).cloned()
                });
                return match ctx {
                    Some(e) if m.contains("revoked") => refuse(403, format!(
                        "{m}: device '{}' was revoked at {} (list version {})",
                        e.name, e.at_ms, snap.version
                    )),
                    _ => refuse(403, m),
                };
            }
        };
        if let Err(m) = self.replay.first_use(&holder, s.nonce, now_ms) {
            return refuse(403, m);
        }
        let Some((method, path)) = s.what.split_once(' ') else {
            return refuse(400, "what must be 'METHOD /path'".into());
        };
        if !matches!(method, "GET" | "POST") || !path.starts_with('/') || path.contains("://") {
            return refuse(400, "what must be 'GET /path' or 'POST /path'".into());
        }
        let h = hex::encode(holder);
        let url = format!("{}{path}", self.upstream);
        match own_core::http::request(method, &url, &[("X-Ce-Holder", &h), ("Content-Type", "application/json")], s.body.as_bytes()) {
            Ok((status, b)) => {
                let upstream = serde_json::from_slice(&b).unwrap_or_else(|_| json!(String::from_utf8_lossy(&b)));
                Outcome::Allowed { holder: h, status, upstream }
            }
            Err(e) => refuse(502, format!("upstream: {e}")),
        }
    }
}
