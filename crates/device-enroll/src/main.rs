use device_enroll::{Enroll, EnrollReq, PairReq};
use own_core::http::{self, Req, Resp};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

const USAGE: &str = "device-enroll id --home DIR\ndevice-enroll serve --home DIR --grant FILE [--dir URL]";

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let home = PathBuf::from(own_core::need("--home", USAGE));
    let id = own_core::keys::load_or_create_secret(&home.join("enroll.secret")).unwrap_or_else(|e| die(&e));
    match cmd.as_str() {
        "id" => println!("{}", id.node_id_hex()),
        "serve" => {
            let grant = std::fs::read_to_string(own_core::need("--grant", USAGE)).unwrap_or_else(|e| die(&e.to_string()));
            let e = Arc::new(Enroll::new(id, &grant).unwrap_or_else(|e| die(&e)));
            let (l, url) = http::bind(0).unwrap_or_else(|e| die(&e.to_string()));
            let dir = own_core::arg("--dir").unwrap_or_else(own_core::dir::default_dir);
            own_core::dir::publish(&dir, "device.enroll", &url, "device.enroll@1: pairing codes and holder-bound device chains")
                .unwrap_or_else(|e| die(&e));
            println!("device.enroll {} on {url}", &e.id_hex()[..16]);
            http::serve(l, Arc::new(move |r: Req| route(&e, r)));
        }
        _ => die(USAGE),
    }
}

fn route(e: &Enroll, r: Req) -> Resp {
    let now = own_core::now_ms();
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/id") => Resp::json(200, &json!({"id": e.id_hex(), "owner": e.owner_hex()})),
        ("GET", "/devices") => Resp::json(200, &json!({"devices": e.devices()})),
        ("POST", "/pair") => match own_core::parse::<PairReq>(&r.body) {
            Err(x) => x,
            Ok(p) => match e.pair(&p, now) {
                Ok((code, exp)) => Resp::json(200, &json!({"code": code, "expires_ms": exp})),
                Err(m) => Resp::json(403, &json!({"error": m})),
            },
        },
        ("POST", "/enroll") => match own_core::parse::<EnrollReq>(&r.body) {
            Err(x) => x,
            Ok(p) => match e.enroll(&p, now) {
                Ok((chain, d)) => {
                    eprintln!("enrolled {} holder {}", d.name, &d.holder[..16]);
                    Resp::json(200, &json!({"chain": chain, "device": d}))
                }
                Err(m) => Resp::json(403, &json!({"error": m})),
            },
        },
        _ => Resp::json(404, &json!({"error": "no such route"})),
    }
}

fn die(m: &str) -> ! {
    eprintln!("device-enroll: {m}");
    std::process::exit(1)
}
