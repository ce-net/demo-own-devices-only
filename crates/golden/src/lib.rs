//! Deterministic golden vectors for the device chains: fixed keys, fixed times, fixed nonces.
//! The schema is ce-net-capability-verify's `vectors.json` (`chains[]` with `root`, `now`,
//! `revoked`, `chain_hex`, `links[]` and the expected `verify_chain`), plus two fields of ours:
//! `holder` (the leaf audience) and `holder_proof` (a signed call and whether it is the holder's).

use ce_net_proto::delegate::{Grant, delegate};
use ce_net_proto::{Caveats, Identity, NodeId, Resource, SignedCapability, cap_bytes, encode_chain, verify_chain};
use own_core::proof::{CALL_DOMAIN, message};
use own_core::{ABILITY_CALL, ABILITY_REVOKE, GROUP_TAG};
use serde_json::{Value, json};

pub const T: u64 = 1_800_000_000;
const DAY: u64 = 24 * 3600;

pub fn key(b: u8) -> Identity {
    Identity::from_secret_bytes(&[b; 32])
}

pub struct Keys {
    pub owner: Identity,
    pub enroll: Identity,
    pub laptop: Identity,
    pub phone: Identity,
    pub desktop: Identity,
    pub friend: Identity,
    pub gate: Identity,
    pub stranger: Identity,
}

pub fn keys() -> Keys {
    Keys {
        owner: key(0x11),
        enroll: key(0x22),
        laptop: key(0x31),
        phone: key(0x32),
        desktop: key(0x33),
        friend: key(0x34),
        gate: key(0x44),
        stranger: key(0x55),
    }
}

fn grant_link(owner: &Identity, enroll: &NodeId) -> SignedCapability {
    SignedCapability::issue(
        owner,
        *enroll,
        vec![ABILITY_CALL.into(), ABILITY_REVOKE.into()],
        Resource::Tag(GROUP_TAG.into()),
        Caveats { not_after: T + 365 * DAY, ..Default::default() },
        1,
        None,
    )
}

fn device_chain(k: &Keys, root: &SignedCapability, device: &Identity, nonce: u64) -> Vec<SignedCapability> {
    let g = Grant { abilities: &[ABILITY_CALL, ABILITY_REVOKE], resource: None, ttl_secs: 30 * DAY, nonce };
    delegate(&[root.clone()], &k.enroll, device.node_id(), &g, T).expect("delegate")
}

fn proof(k: &Keys, chain_hex: &str, signer: &Identity, expect: &str) -> Value {
    let m = message(CALL_DOMAIN, &k.gate.node_id_hex(), chain_hex, (T + 60) * 1000, 7, "GET /v1/quote", "");
    json!({
        "receiver": k.gate.node_id_hex(),
        "message_hex": hex::encode(&m),
        "signer": signer.node_id_hex(),
        "sig": hex::encode(signer.sign(&m)),
        "expect": expect,
    })
}

fn vector(name: &str, what: &str, root: &NodeId, now: u64, revoked: &[(NodeId, u64)], chain: &[SignedCapability], proof: Option<Value>) -> Value {
    let is_rev = |i: &NodeId, n: u64| revoked.iter().any(|(a, b)| a == i && *b == n);
    let vc = match verify_chain(chain, root, now, &is_rev) {
        Ok(_) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "error": e}),
    };
    let links: Vec<Value> = chain
        .iter()
        .map(|l| {
            json!({
                "issuer": hex::encode(l.cap.issuer),
                "audience": hex::encode(l.cap.audience),
                "abilities": l.cap.abilities,
                "nonce": l.cap.nonce,
                "not_after": l.cap.caveats.not_after,
                "cap_bytes": hex::encode(cap_bytes(&l.cap)),
                "cap_id": hex::encode(l.id()),
                "sig": hex::encode(l.sig),
            })
        })
        .collect();
    let mut v = json!({
        "name": name,
        "what": what,
        "root": hex::encode(root),
        "now": now,
        "revoked": revoked.iter().map(|(i, n)| json!({"issuer": hex::encode(i), "nonce": n})).collect::<Vec<_>>(),
        "chain_hex": encode_chain(chain),
        "links": links,
        "holder": hex::encode(chain.last().unwrap().cap.audience),
        "verify_chain": vc,
    });
    if let Some(p) = proof {
        v["holder_proof"] = p;
    }
    v
}

pub fn vectors() -> Value {
    let k = keys();
    let owner = k.owner.node_id();
    let root = grant_link(&k.owner, &k.enroll.node_id());
    let laptop = device_chain(&k, &root, &k.laptop, 101);
    let phone = device_chain(&k, &root, &k.phone, 102);
    let desktop = device_chain(&k, &root, &k.desktop, 103);
    let enroll = k.enroll.node_id();
    let phone_rev = [(enroll, 102u64)];
    let now = T + 60;
    let hx = encode_chain;

    // The enroll cell tries to give a device more than the owner gave the cell.
    let mut wide = vec![root.clone()];
    wide.push(SignedCapability::issue(
        &k.enroll,
        k.phone.node_id(),
        vec![ABILITY_CALL.into(), "billing:*".into()],
        Resource::Tag(GROUP_TAG.into()),
        Caveats { not_after: T + 30 * DAY, ..Default::default() },
        104,
        Some(root.id()),
    ));
    // The phone passes its key on to the friend with a longer life than its own.
    let mut onward = phone.clone();
    let last = onward.last().unwrap().clone();
    onward.push(SignedCapability::issue(
        &k.phone,
        k.friend.node_id(),
        vec![ABILITY_CALL.into()],
        Resource::Tag(GROUP_TAG.into()),
        Caveats { not_after: T + 400 * DAY, ..Default::default() },
        105,
        Some(last.id()),
    ));
    // Someone else's owner key enrolls a "phone" of their own.
    let other_root = grant_link(&k.stranger, &k.enroll.node_id());
    let other = device_chain(&k, &other_root, &k.phone, 106);

    let v = vec![
        vector("laptop", "the laptop's chain; the laptop signs the call", &owner, now, &[], &laptop, Some(proof(&k, &hx(&laptop), &k.laptop, "match"))),
        vector("phone", "the phone's chain; the phone signs the call", &owner, now, &[], &phone, Some(proof(&k, &hx(&phone), &k.phone, "match"))),
        vector("desktop", "the desktop's chain; the desktop signs the call", &owner, now, &[], &desktop, Some(proof(&k, &hx(&desktop), &k.desktop, "match"))),
        vector(
            "phone-key-copied-to-friend",
            "the phone's key file on the friend's device: the chain itself is valid, the call is signed by the friend, not the holder",
            &owner, now, &[], &phone, Some(proof(&k, &hx(&phone), &k.friend, "mismatch")),
        ),
        vector("phone-revoked", "the phone's link (enroll, 102) is on the revocation list", &owner, now, &phone_rev, &phone, None),
        vector("laptop-after-phone-revoked", "the same revocation list; the laptop is untouched", &owner, now, &phone_rev, &laptop, Some(proof(&k, &hx(&laptop), &k.laptop, "match"))),
        vector("desktop-after-phone-revoked", "the same revocation list; the desktop is untouched", &owner, now, &phone_rev, &desktop, None),
        vector("phone-after-30-days", "a device chain lives 30 days", &owner, T + 30 * DAY + 1, &[], &phone, None),
        vector("enroll-widens-ability", "the enroll cell cannot grant what the owner did not give it", &owner, now, &[], &wide, None),
        vector("phone-passes-on-longer-life", "a device cannot hand on a key that outlives its own", &owner, now, &[], &onward, None),
        vector("other-owner", "a chain rooted at someone else's owner key", &owner, now, &[], &other, None),
    ];
    json!({
        "about": "Holder-bound device chains of demo-own-devices-only. Keys are bytes [b;32] for owner 0x11, enroll 0x22, laptop 0x31, phone 0x32, desktop 0x33, friend 0x34, gate 0x44, other owner 0x55. Regenerate: cargo run -p golden > golden/vectors.json",
        "chains": v,
    })
}
