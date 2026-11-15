use own_core::http::{self, Req, Resp};
use own_core::proof::Signed;
use revoke_list::RevokeList;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

const USAGE: &str = "revoke-list id --home DIR\nrevoke-list serve --home DIR --owner-pub FILE [--dir URL]";

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let home = PathBuf::from(own_core::need("--home", USAGE));
    let id = own_core::keys::load_or_create_secret(&home.join("revoke-list.secret")).unwrap_or_else(|e| die(&e));
    match cmd.as_str() {
        "id" => println!("{}", id.node_id_hex()),
        "serve" => {
            let owner = own_core::keys::read_pub(own_core::need("--owner-pub", USAGE).as_ref()).unwrap_or_else(|e| die(&e));
            let rl = Arc::new(RevokeList::new(id, owner));
            let (l, url) = http::bind(0).unwrap_or_else(|e| die(&e.to_string()));
            let dir = own_core::arg("--dir").unwrap_or_else(own_core::dir::default_dir);
            own_core::dir::publish(&dir, "revoke.list", &url, "revoke.list@1: revoked device links, signed fresh on every read")
                .unwrap_or_else(|e| die(&e));
            println!("revoke.list {} on {url}", &rl.id_hex()[..16]);
            http::serve(l, Arc::new(move |r: Req| route(&rl, r)));
        }
        _ => die(USAGE),
    }
}

fn route(rl: &RevokeList, r: Req) -> Resp {
    let now = own_core::now_ms();
    match (r.method.as_str(), r.path.as_str()) {
        ("GET", "/id") => Resp::json(200, &json!({"id": rl.id_hex()})),
        ("GET", "/list") => Resp::json(200, &serde_json::to_value(rl.list(now)).unwrap()),
        ("POST", "/revoke") => match own_core::parse::<Signed>(&r.body) {
            Err(x) => x,
            Ok(s) => match rl.revoke(&s, now) {
                Ok(e) => {
                    eprintln!("revoked {} ({}:{}) at {}", e.name, &e.issuer[..16], e.nonce, e.at_ms);
                    Resp::json(200, &json!({"revoked": e}))
                }
                Err(m) => Resp::json(403, &json!({"error": m})),
            },
        },
        _ => Resp::json(404, &json!({"error": "no such route"})),
    }
}

fn die(m: &str) -> ! {
    eprintln!("revoke-list: {m}");
    std::process::exit(1)
}
