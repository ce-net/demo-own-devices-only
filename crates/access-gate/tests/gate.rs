//! The gate's refusals that the four-device run does not show: no list, a stale list, a forged
//! list, an older list, a replayed call, a call for another gate.

use access_gate::{Gate, Outcome};
use ce_net_proto::delegate::{Grant, delegate};
use ce_net_proto::{Caveats, Identity, Resource, SignedCapability, encode_chain};
use own_core::http::{self, Resp};
use own_core::proof::{CALL_DOMAIN, sign};
use own_core::{ABILITY_CALL, GROUP_TAG, now_ms, now_s};
use revoke_list::RevokeList;
use std::sync::Arc;

fn id(b: u8) -> Identity {
    Identity::from_secret_bytes(&[b; 32])
}

struct World {
    gate: Gate,
    list: RevokeList,
    device: Identity,
    chain: String,
}

fn world() -> World {
    let (owner, enroll, device, gate, list) = (id(1), id(2), id(3), id(4), id(5));
    let root = SignedCapability::issue(
        &owner,
        enroll.node_id(),
        vec![ABILITY_CALL.into()],
        Resource::Tag(GROUP_TAG.into()),
        Caveats { not_after: now_s() + 3600, ..Default::default() },
        1,
        None,
    );
    let g = Grant { abilities: &[ABILITY_CALL], resource: None, ttl_secs: 600, nonce: 2 };
    let chain = encode_chain(&delegate(&[root], &enroll, device.node_id(), &g, now_s()).unwrap());
    let (l, url) = http::bind(0).unwrap();
    std::thread::spawn(move || http::serve(l, Arc::new(|_| Resp::json(200, &serde_json::json!({"paid": true})))));
    let list_key = list.node_id();
    World {
        gate: Gate::new(gate, owner.node_id(), ABILITY_CALL, &url, list_key),
        list: RevokeList::new(list, owner.node_id()),
        device,
        chain,
    }
}

fn reason(o: Outcome) -> String {
    match o {
        Outcome::Allowed { .. } => "allowed".into(),
        Outcome::Refused { reason, .. } => reason,
    }
}

#[test]
fn refuses_everything_until_it_holds_a_fresh_list() {
    let w = world();
    let s = sign(&w.device, CALL_DOMAIN, &w.gate.id_hex(), &w.chain, "GET /v1/quote", "");
    let t = s.ts;
    assert!(reason(w.gate.call(&s, t)).contains("no revocation list yet"));
    w.gate.adopt(&w.list.list(t)).unwrap();
    assert_eq!(reason(w.gate.call(&s, t)), "allowed");
    let later = sign(&w.device, CALL_DOMAIN, &w.gate.id_hex(), &w.chain, "GET /v1/quote", "");
    assert!(reason(w.gate.call(&later, t + 10_000)).contains("refusing every call"));
}

#[test]
fn a_replayed_call_is_refused() {
    let w = world();
    let s = sign(&w.device, CALL_DOMAIN, &w.gate.id_hex(), &w.chain, "GET /v1/quote", "");
    let t = s.ts; // one clock reading, so a slow machine cannot make the list stale mid-test
    w.gate.adopt(&w.list.list(t)).unwrap();
    assert_eq!(reason(w.gate.call(&s, t)), "allowed");
    assert!(reason(w.gate.call(&s, t)).contains("replayed"));
}

#[test]
fn a_call_signed_for_another_gate_fails_the_holder_proof() {
    let w = world();
    let s = sign(&w.device, CALL_DOMAIN, &id(9).node_id_hex(), &w.chain, "GET /v1/quote", "");
    w.gate.adopt(&w.list.list(s.ts)).unwrap();
    assert!(reason(w.gate.call(&s, s.ts)).contains("holder proof does not match"));
}

#[test]
fn forged_and_older_lists_are_not_adopted() {
    let w = world();
    let forged = RevokeList::new(id(6), id(1).node_id()).list(now_ms());
    assert!(w.gate.adopt(&forged).unwrap_err().contains("pinned"));
    let old = w.list.list(now_ms() - 1000);
    w.gate.adopt(&w.list.list(now_ms())).unwrap();
    assert!(w.gate.adopt(&old).unwrap_err().contains("older"));
}
