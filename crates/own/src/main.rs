//! `own`: the owner's and the devices' side of the demo.

mod report;

use ce_net_proto::{Caveats, Resource, SignedCapability, encode_chain};
use own_core::proof::{self, CALL_DOMAIN, REVOKE_DOMAIN};
use own_core::{dir, http, keys, need};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

const USAGE: &str = "\
own owner init   --home DIR
own owner grant  --home DIR --to ENROLL_ID --out FILE
own owner pair   --home DIR
own device enroll --home DIR --name NAME --code CODE
own device call   --home DIR [--what 'GET /v1/quote']
own device loop   --home DIR --log FILE --stop FILE [--every-ms 100]
own device revoke --home DIR --name NAME
own report --run DIR
All but init/grant/report find cells in the directory at --dir or $CE_DIR.";

/// The key file: what device.enroll issued to this device. Not secret on its own.
#[derive(Serialize, Deserialize, Clone)]
struct KeyFile {
    name: String,
    holder: String,
    chain: String,
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r = match (a.get(1).map(String::as_str), a.get(2).map(String::as_str)) {
        (Some("owner"), Some("init")) => owner_init(),
        (Some("owner"), Some("grant")) => owner_grant(),
        (Some("owner"), Some("pair")) => owner_pair(),
        (Some("device"), Some("enroll")) => enroll(),
        (Some("device"), Some("call")) => call_once(),
        (Some("device"), Some("loop")) => call_loop(),
        (Some("device"), Some("revoke")) => revoke(),
        (Some("report"), _) => report::run(Path::new(&need("--run", USAGE))),
        _ => Err(USAGE.to_string()),
    };
    if let Err(e) = r {
        eprintln!("own: {e}");
        std::process::exit(1);
    }
}

fn home() -> PathBuf {
    PathBuf::from(need("--home", USAGE))
}

fn dir_url() -> String {
    own_core::arg("--dir").unwrap_or_else(dir::default_dir)
}

fn cell_id(url: &str) -> Result<String, String> {
    let (_, v) = http::get_json(&format!("{url}/id"))?;
    v["id"].as_str().map(str::to_string).ok_or_else(|| format!("{url}/id: no id"))
}

fn owner_init() -> Result<(), String> {
    let h = home();
    let id = keys::load_or_create_secret(&h.join("owner.secret"))?;
    std::fs::write(h.join("owner.pub"), id.node_id_hex()).map_err(|e| e.to_string())?;
    println!("{}", id.node_id_hex());
    Ok(())
}

/// Link 0: owner -> enroll cell. The widest anything below it can ever be.
fn owner_grant() -> Result<(), String> {
    let id = keys::load_secret(&home().join("owner.secret"))?;
    let to = ce_net_proto::identity::node_id_from_hex(&need("--to", USAGE)).map_err(|e| e.0)?;
    let link = SignedCapability::issue(
        &id,
        to,
        vec![own_core::ABILITY_CALL.into(), own_core::ABILITY_REVOKE.into()],
        Resource::Tag(own_core::GROUP_TAG.into()),
        Caveats { not_after: own_core::now_s() + 365 * 24 * 3600, ..Default::default() },
        keys::random_u64(),
        None,
    );
    std::fs::write(need("--out", USAGE), encode_chain(&[link])).map_err(|e| e.to_string())
}

fn owner_pair() -> Result<(), String> {
    let id = keys::load_secret(&home().join("owner.secret"))?;
    let url = dir::find(&dir_url(), "device.enroll")?;
    let eid = cell_id(&url)?;
    let ts = own_core::now_ms();
    let sig = hex::encode(id.sign(&device_enroll::pair_message(&eid, ts)));
    let (st, v) = http::post_json(&format!("{url}/pair"), &json!({"ts": ts, "sig": sig}))?;
    if st != 200 {
        return Err(format!("pair: {}", v["error"]));
    }
    println!("{}", v["code"].as_str().unwrap_or(""));
    Ok(())
}

fn enroll() -> Result<(), String> {
    let h = home();
    let name = need("--name", USAGE);
    let code = need("--code", USAGE);
    let id = keys::load_or_create_secret(&h.join("device.secret"))?;
    let url = dir::find(&dir_url(), "device.enroll")?;
    let eid = cell_id(&url)?;
    let ts = own_core::now_ms();
    let sig = hex::encode(id.sign(&device_enroll::enroll_message(&eid, ts, &name, &code)));
    let req = json!({"code": code, "name": name, "holder": id.node_id_hex(), "ts": ts, "sig": sig});
    let (st, v) = http::post_json(&format!("{url}/enroll"), &req)?;
    if st != 200 {
        return Err(format!("enroll: {}", v["error"]));
    }
    let kf = KeyFile { name: name.clone(), holder: id.node_id_hex(), chain: v["chain"].as_str().unwrap_or("").into() };
    std::fs::write(h.join("device.key"), serde_json::to_string_pretty(&kf).unwrap()).map_err(|e| e.to_string())?;
    println!("enrolled {name}: key {}..., chain of 2 links, valid until {}", &kf.holder[..16], v["device"]["not_after"]);
    Ok(())
}

fn load_device(h: &Path) -> Result<(ce_net_proto::Identity, KeyFile), String> {
    let id = keys::load_or_create_secret(&h.join("device.secret"))?;
    let s = std::fs::read_to_string(h.join("device.key")).map_err(|e| format!("device.key: {e}"))?;
    let kf: KeyFile = serde_json::from_str(&s).map_err(|e| format!("device.key: {e}"))?;
    Ok((id, kf))
}

struct Caller {
    id: ce_net_proto::Identity,
    kf: KeyFile,
    gate: String,
    gate_id: String,
}

impl Caller {
    fn new(h: &Path) -> Result<Self, String> {
        let (id, kf) = load_device(h)?;
        let gate = dir::find(&dir_url(), "access.gate")?;
        let gate_id = cell_id(&gate)?;
        Ok(Caller { id, kf, gate, gate_id })
    }

    fn call(&self, what: &str) -> Result<(u16, Value), String> {
        let s = proof::sign(&self.id, CALL_DOMAIN, &self.gate_id, &self.kf.chain, what, "");
        http::post_json(&format!("{}/call", self.gate), &serde_json::to_value(&s).unwrap())
    }
}

fn call_once() -> Result<(), String> {
    let c = Caller::new(&home())?;
    let (st, v) = c.call(&own_core::arg("--what").unwrap_or_else(|| "GET /v1/quote".into()))?;
    println!("{v}");
    if st == 200 { Ok(()) } else { Err(format!("refused ({st})")) }
}

/// Call the gate every `--every-ms` until the stop file exists; one JSON line per call.
fn call_loop() -> Result<(), String> {
    let h = home();
    let label = h.file_name().and_then(|x| x.to_str()).unwrap_or("device").to_string();
    let c = Caller::new(&h)?;
    let log = need("--log", USAGE);
    let stop = PathBuf::from(need("--stop", USAGE));
    let every: u64 = own_core::arg("--every-ms").and_then(|x| x.parse().ok()).unwrap_or(100);
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(&log).map_err(|e| e.to_string())?;
    while !stop.exists() {
        let t0 = own_core::now_ms();
        let line = match c.call("GET /v1/quote") {
            Ok((st, v)) => json!({"device": label, "key_of": c.kf.name, "t0": t0, "t1": own_core::now_ms(), "status": st,
                                  "ok": v["ok"] == true, "reason": v["reason"], "upstream": v["upstream"]}),
            Err(e) => json!({"device": label, "key_of": c.kf.name, "t0": t0, "t1": own_core::now_ms(), "status": 0, "ok": false, "reason": e}),
        };
        use std::io::Write;
        writeln!(out, "{line}").map_err(|e| e.to_string())?;
        std::thread::sleep(std::time::Duration::from_millis(every));
    }
    Ok(())
}

fn revoke() -> Result<(), String> {
    let (id, kf) = load_device(&home())?;
    let target = need("--name", USAGE);
    let d = dir_url();
    let enroll = dir::find(&d, "device.enroll")?;
    let (_, v) = http::get_json(&format!("{enroll}/devices"))?;
    let dev = v["devices"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"] == target.as_str()))
        .ok_or_else(|| format!("no enrolled device named {target}"))?;
    let what = revoke_list::revoke_subject(
        dev["issuer"].as_str().unwrap_or(""),
        dev["nonce"].as_u64().unwrap_or(0),
        dev["holder"].as_str().unwrap_or(""),
        &target,
    );
    let list = dir::find(&d, "revoke.list")?;
    let lid = cell_id(&list)?;
    let s = proof::sign(&id, REVOKE_DOMAIN, &lid, &kf.chain, &what, "");
    let (st, v) = http::post_json(&format!("{list}/revoke"), &serde_json::to_value(&s).unwrap())?;
    if st != 200 {
        return Err(format!("revoke: {}", v["error"]));
    }
    println!("{}", json!({"revoked": target, "from": kf.name, "at_ms": v["revoked"]["at_ms"]}));
    Ok(())
}
