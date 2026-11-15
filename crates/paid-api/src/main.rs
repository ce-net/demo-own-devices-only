//! The example upstream behind access.gate: a paid API with no auth of its own. It listens on
//! 127.0.0.1 only and is never listed in the directory; the gate is the only way in.

use own_core::http::{self, Req, Resp};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn main() {
    let (l, url) = http::bind(0).expect("bind");
    println!("{url}");
    let n = Arc::new(AtomicU64::new(0));
    http::serve(
        l,
        Arc::new(move |r: Req| match r.path.as_str() {
            "/v1/quote" => {
                let i = n.fetch_add(1, Ordering::SeqCst) + 1;
                Resp::json(200, &json!({"quote": "EURSEK 11.42", "call": i, "billed_to": "owner"}))
            }
            _ => Resp::json(404, &json!({"error": "no such route"})),
        }),
    );
}
