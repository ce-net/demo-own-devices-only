use ce_net_proto::{decode_chain, verify_chain};

fn committed() -> serde_json::Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../golden/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("golden/vectors.json")).unwrap()
}

#[test]
fn committed_vectors_are_reproduced_byte_for_byte() {
    assert_eq!(golden::vectors(), committed(), "regenerate: cargo run -p golden > golden/vectors.json");
}

#[test]
fn expectations_hold_and_holder_proofs_decide() {
    let v = committed();
    let mut n = 0;
    for c in v["chains"].as_array().unwrap() {
        let chain = decode_chain(c["chain_hex"].as_str().unwrap()).unwrap();
        let root = ce_net_proto::identity::node_id_from_hex(c["root"].as_str().unwrap()).unwrap();
        let rev: Vec<(String, u64)> = c["revoked"].as_array().unwrap().iter()
            .map(|r| (r["issuer"].as_str().unwrap().to_string(), r["nonce"].as_u64().unwrap())).collect();
        let got = verify_chain(&chain, &root, c["now"].as_u64().unwrap(), &|i, n| rev.iter().any(|(a, b)| *a == hex::encode(i) && *b == n));
        assert_eq!(got.is_ok(), c["verify_chain"]["ok"] == true, "{}", c["name"]);
        if let Some(p) = c.get("holder_proof") {
            let holder = chain.last().unwrap().cap.audience;
            let m = hex::decode(p["message_hex"].as_str().unwrap()).unwrap();
            let sig: [u8; 64] = hex::decode(p["sig"].as_str().unwrap()).unwrap().try_into().unwrap();
            let ok = ce_net_proto::identity::verify(&holder, &m, &sig).is_ok();
            assert_eq!(ok, p["expect"] == "match", "{}", c["name"]);
        }
        n += 1;
    }
    assert_eq!(n, 11);
}
