//! device.enroll@1.
//!
//! The cell holds one link from the owner: `owner -> enroll`, `may` [`ABILITY_CALL`] and
//! [`ABILITY_REVOKE`] on `Tag(GROUP_TAG)`. It never holds the owner's secret.
//!
//! 1. `Pair`: the owner signs a request; the cell answers a one-time code (`XXXX-XXXX`, 2 minutes).
//! 2. `Enroll`: a device sends the code, a name, its public key, and a signature by that key. The
//!    cell burns the code and delegates `enroll -> device`: the same abilities, the same tag, 30 days,
//!    a fresh nonce. The chain's leaf audience is the device key, so only that device can use it.
//! 3. `Devices`: names, holder keys and link nonces of enrolled devices (what revoke needs).

use ce_net_proto::{Identity, NodeId, SignedCapability, decode_chain, delegate, encode_chain};
use own_core::proof::{self, ENROLL_DOMAIN, PAIR_DOMAIN};
use own_core::{ABILITY_CALL, ABILITY_REVOKE};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

pub const CODE_TTL_MS: u64 = 120_000;
pub const DEVICE_TTL_S: u64 = 30 * 24 * 3600;
const MAX_BAD_CODES: u32 = 20;
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub holder: String,
    pub issuer: String,
    pub nonce: u64,
    pub not_after: u64,
    pub enrolled_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct PairReq {
    pub ts: u64,
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrollReq {
    pub code: String,
    pub name: String,
    pub holder: String,
    pub ts: u64,
    pub sig: String,
}

struct Code {
    code: String,
    expires_ms: u64,
}

pub struct Enroll {
    id: Identity,
    grant: Vec<SignedCapability>,
    owner: NodeId,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    codes: Vec<Code>,
    bad: u32,
    devices: Vec<Device>,
    seen: Vec<(u64, String)>,
}

/// What the owner signs to ask for a pairing code.
pub fn pair_message(enroll_hex: &str, ts: u64) -> Vec<u8> {
    proof::message(PAIR_DOMAIN, enroll_hex, "", ts, 0, "pair", "")
}

/// What a device signs to enroll.
pub fn enroll_message(enroll_hex: &str, ts: u64, name: &str, code: &str) -> Vec<u8> {
    proof::message(ENROLL_DOMAIN, enroll_hex, "", ts, 0, &format!("enroll {name} {code}"), "")
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sig64(h: &str) -> Option<[u8; 64]> {
    hex::decode(h).ok()?.try_into().ok()
}

impl Enroll {
    pub fn new(id: Identity, grant_hex: &str) -> Result<Self, String> {
        let grant = decode_chain(grant_hex).map_err(|e| e.0)?;
        let leaf = grant.last().ok_or("empty grant")?;
        if leaf.cap.audience != id.node_id() {
            return Err("the grant is not issued to this enroll cell's key".into());
        }
        let owner = grant[0].cap.issuer;
        Ok(Enroll { id, grant, owner, state: Mutex::new(State::default()) })
    }

    pub fn id_hex(&self) -> String {
        self.id.node_id_hex()
    }

    pub fn owner_hex(&self) -> String {
        hex::encode(self.owner)
    }

    fn fresh(ts: u64, now: u64) -> Result<(), String> {
        if ts.abs_diff(now) > proof::MAX_SKEW_MS {
            return Err("request timestamp is too far from this cell's clock".into());
        }
        Ok(())
    }

    /// The owner asks for a pairing code.
    pub fn pair(&self, r: &PairReq, now: u64) -> Result<(String, u64), String> {
        Self::fresh(r.ts, now)?;
        let sig = sig64(&r.sig).ok_or("bad signature")?;
        ce_net_proto::identity::verify(&self.owner, &pair_message(&self.id_hex(), r.ts), &sig)
            .map_err(|_| "pairing codes are only issued to the owner")?;
        let mut s = self.state.lock().unwrap();
        if s.seen.iter().any(|(t, x)| *t == r.ts && x == &r.sig) {
            return Err("replayed pair request".into());
        }
        s.seen.push((r.ts, r.sig.clone()));
        s.seen.retain(|(t, _)| now.saturating_sub(*t) < 2 * proof::MAX_SKEW_MS);
        let rnd = own_core::keys::random32();
        let mut code = String::new();
        for (i, b) in rnd.iter().take(8).enumerate() {
            if i == 4 {
                code.push('-');
            }
            code.push(ALPHABET[*b as usize % ALPHABET.len()] as char);
        }
        let expires_ms = now + CODE_TTL_MS;
        s.codes.retain(|c| c.expires_ms > now);
        s.codes.push(Code { code: code.clone(), expires_ms });
        s.bad = 0;
        Ok((code, expires_ms))
    }

    /// A device redeems a code. Returns the holder-bound chain.
    pub fn enroll(&self, r: &EnrollReq, now: u64) -> Result<(String, Device), String> {
        Self::fresh(r.ts, now)?;
        if r.name.is_empty() || r.name.len() > 32 || !r.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("name: 1-32 of a-z 0-9 -".into());
        }
        let holder = ce_net_proto::identity::node_id_from_hex(&r.holder).map_err(|e| e.0)?;
        let sig = sig64(&r.sig).ok_or("bad signature")?;
        ce_net_proto::identity::verify(&holder, &enroll_message(&self.id_hex(), r.ts, &r.name, &r.code), &sig)
            .map_err(|_| "the enrollment is not signed by the key it asks a chain for")?;
        let mut s = self.state.lock().unwrap();
        if s.bad >= MAX_BAD_CODES {
            return Err("too many wrong codes; ask the owner for a new one".into());
        }
        s.codes.retain(|c| c.expires_ms > now);
        let hit = s.codes.iter().position(|c| ct_eq(c.code.as_bytes(), r.code.trim().to_uppercase().as_bytes()));
        let Some(i) = hit else {
            s.bad += 1;
            return Err("unknown or expired pairing code".into());
        };
        s.codes.remove(i);
        if s.devices.iter().any(|d| d.name == r.name) {
            return Err(format!("a device named {} is already enrolled", r.name));
        }
        let nonce = own_core::keys::random_u64();
        let grant = ce_net_proto::delegate::Grant {
            abilities: &[ABILITY_CALL, ABILITY_REVOKE],
            resource: None,
            ttl_secs: DEVICE_TTL_S,
            nonce,
        };
        let chain = delegate::delegate(&self.grant, &self.id, holder, &grant, now / 1000).map_err(|e| e.0)?;
        let leaf = &chain.last().unwrap().cap;
        let d = Device {
            name: r.name.clone(),
            holder: r.holder.clone(),
            issuer: self.id_hex(),
            nonce,
            not_after: leaf.caveats.not_after,
            enrolled_ms: now,
        };
        s.devices.push(d.clone());
        Ok((encode_chain(&chain), d))
    }

    pub fn devices(&self) -> Vec<Device> {
        self.state.lock().unwrap().devices.clone()
    }
}
