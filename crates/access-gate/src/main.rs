use access_gate::{Gate, Outcome, POLL_MS};
use own_core::http::{self, Req, Resp};
use own_core::proof::Signed;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

const USAGE: &str = "access-gate id --home DIR\n\
access-gate serve --home DIR --owner-pub FILE --list-pub FILE --upstream URL [--action ABILITY] [--dir URL]";

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let home = PathBuf::from(own_core::need("--home", USAGE));
    let id = own_core::keys::load_or_create_secret(&home.join("gate.secret")).unwrap_or_else(|e| die(&e));
    match cmd.as_str() {
        "id" => println!("{}", id.node_id_hex()),
        "serve" => {
            let owner = own_core::keys::read_pub(own_core::need("--owner-pub", USAGE).as_ref()).unwrap_or_else(|e| die(&e));
            let list_key = own_core::keys::read_pub(own_core::need("--list-pub", USAGE).as_ref()).unwrap_or_else(|e| die(&e));
            let upstream = own_core::need("--upstream", USAGE);
            let action = own_core::arg("--action").unwrap_or_else(|| own_core::ABILITY_CALL.into());
            let dir = own_core::arg("--dir").unwrap_or_else(own_core::dir::default_dir);
            let list_url = own_core::dir::find(&dir, "revoke.list").unwrap_or_else(|e| die(&e));
            let g = Arc::new(Gate::new(id, owner, &action, &upstream, list_key));
            let pg = g.clone();
            std::thread::spawn(move || {
                loop {
                    match own_core::http::get_json(&format!("{list_url}/list"))
                        .and_then(|(_, v)| serde_json::from_value(v).map_err(|e| e.to_string()))
                        .and_then(|l| pg.adopt(&l))
                    {
                        Ok(()) => {}
                        Err(e) => eprintln!("access.gate: revocation list: {e}"),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
                }
            });
            let (l, url) = http::bind(0).unwrap_or_else(|e| die(&e.to_string()));
            own_core::dir::publish(&dir, "access.gate", &url, "access.gate@1: holder-bound chains and revocation in front of an upstream")
                .unwrap_or_else(|e| die(&e));
            println!("access.gate {} on {url} -> {upstream}", &g.id_hex()[..16]);
            http::serve(l, Arc::new(move |r: Req| route(&g, r)));
        }
        _ => die(USAGE),
    }
}

fn route(g: &Gate, r: Req) -> Resp {
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/id") => Resp::json(200, &json!({"id": g.id_hex()})),
        ("POST", "/call") => match own_core::parse::<Signed>(&r.body) {
            Err(x) => x,
            Ok(s) => match g.call(&s, own_core::now_ms()) {
                Outcome::Allowed { holder, status, upstream } => {
                    Resp::json(200, &json!({"ok": true, "holder": holder, "upstream_status": status, "upstream": upstream}))
                }
                Outcome::Refused { status, reason } => {
                    Resp::json(status, &json!({"ok": false, "refused_by": "access.gate", "reason": reason}))
                }
            },
        },
        _ => Resp::json(404, &json!({"error": "no such route"})),
    }
}

fn die(m: &str) -> ! {
    eprintln!("access-gate: {m}");
    std::process::exit(1)
}
