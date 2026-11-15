//! revoke.list@1.
//!
//! `Revoke`: a signed request from an enrolled device whose chain grants `devices:revoke`
//! (checked with ce-net-proto `authorize`, so a revoked device cannot revoke anyone). The target is
//! one chain link, named the way ce-net-proto names it: `(issuer, nonce)`.
//!
//! `List`: the entries, with a version and the time of this read, signed by this cell's key on
//! every read. A gate pins the key and refuses a list that is unsigned, older than it has seen, or
//! not fresh; when it cannot get a fresh list it refuses every call (fail closed).

use ce_net_proto::{Identity, NodeId};
use own_core::proof::{self, LIST_DOMAIN, REVOKE_DOMAIN, Replay, Signed};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Who the device is called, for people.
    pub name: String,
    /// The device key the revoked link was issued to, hex.
    pub holder: String,
    /// The revoked link: its issuer (hex) and nonce.
    pub issuer: String,
    pub nonce: u64,
    /// The revoked device that asked, hex.
    pub by: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub list: String,
    pub version: u64,
    pub issued_ms: u64,
    pub entries: Vec<Entry>,
}

/// The wire form of a list: the exact JSON bytes that were signed, and the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedList {
    pub body: String,
    pub sig: String,
}

/// The `what` of a revoke request.
pub fn revoke_subject(issuer_hex: &str, nonce: u64, holder_hex: &str, name: &str) -> String {
    format!("revoke {issuer_hex}:{nonce} holder {holder_hex} name {name}")
}

fn parse_subject(w: &str) -> Option<(String, u64, String, String)> {
    let mut p = w.split(' ');
    if p.next()? != "revoke" {
        return None;
    }
    let (iss, n) = p.next()?.split_once(':')?;
    if p.next()? != "holder" {
        return None;
    }
    let holder = p.next()?.to_string();
    if p.next()? != "name" {
        return None;
    }
    let name = p.next()?.to_string();
    Some((iss.to_string(), n.parse().ok()?, holder, name))
}

/// Check a list against the pinned key; returns the snapshot.
pub fn verify_list(l: &SignedList, key: &NodeId) -> Result<Snapshot, String> {
    let sig: [u8; 64] = hex::decode(&l.sig).ok().and_then(|b| b.try_into().ok()).ok_or("list: bad signature")?;
    let mut m = LIST_DOMAIN.as_bytes().to_vec();
    m.push(b'\n');
    m.extend_from_slice(l.body.as_bytes());
    ce_net_proto::identity::verify(key, &m, &sig).map_err(|_| "list: not signed by the pinned revoke.list key")?;
    serde_json::from_str(&l.body).map_err(|e| format!("list: {e}"))
}

pub struct RevokeList {
    id: Identity,
    owner: NodeId,
    replay: Replay,
    state: Mutex<(u64, Vec<Entry>)>,
}

impl RevokeList {
    pub fn new(id: Identity, owner: NodeId) -> Self {
        RevokeList { id, owner, replay: Replay::default(), state: Mutex::new((0, Vec::new())) }
    }

    pub fn id_hex(&self) -> String {
        self.id.node_id_hex()
    }

    fn is_revoked(&self, issuer: &NodeId, nonce: u64) -> bool {
        let iss = hex::encode(issuer);
        self.state.lock().unwrap().1.iter().any(|e| e.issuer == iss && e.nonce == nonce)
    }

    pub fn revoke(&self, s: &Signed, now_ms: u64) -> Result<Entry, String> {
        let by = proof::authorize(
            REVOKE_DOMAIN,
            &self.id.node_id(),
            &self.owner,
            s,
            own_core::ABILITY_REVOKE,
            now_ms,
            &|i, n| self.is_revoked(i, n),
        )?;
        self.replay.first_use(&by, s.nonce, now_ms)?;
        let (issuer, nonce, holder, name) = parse_subject(&s.what).ok_or("bad revoke subject")?;
        ce_net_proto::identity::node_id_from_hex(&issuer).map_err(|e| e.0)?;
        ce_net_proto::identity::node_id_from_hex(&holder).map_err(|e| e.0)?;
        let mut st = self.state.lock().unwrap();
        if let Some(e) = st.1.iter().find(|e| e.issuer == issuer && e.nonce == nonce) {
            return Ok(e.clone());
        }
        let e = Entry { name, holder, issuer, nonce, by: hex::encode(by), at_ms: now_ms };
        st.0 += 1;
        st.1.push(e.clone());
        Ok(e)
    }

    /// The list, signed now.
    pub fn list(&self, now_ms: u64) -> SignedList {
        let st = self.state.lock().unwrap();
        let snap = Snapshot { list: self.id_hex(), version: st.0, issued_ms: now_ms, entries: st.1.clone() };
        let body = serde_json::to_string(&snap).unwrap();
        let mut m = LIST_DOMAIN.as_bytes().to_vec();
        m.push(b'\n');
        m.extend_from_slice(body.as_bytes());
        SignedList { body, sig: hex::encode(self.id.sign(&m)) }
    }
}
