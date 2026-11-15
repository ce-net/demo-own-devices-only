//! Shared pieces of the own-devices cells.
//!
//! - [`http`]: a small HTTP/1.1 server (one thread per connection) and client, `Connection: close`.
//! - [`keys`]: a device's secret key file (never leaves the device) and its key file (the chain).
//! - [`proof`]: the bytes a holder signs to prove a request comes from the chain's holder.
//! - [`dir`]: publish and find cells in a ce-net directory (the live MCP server or ce-net-local-dev-sim).

pub mod dir;
pub mod http;
pub mod keys;
pub mod proof;

/// Unix time in milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Unix time in seconds.
pub fn now_s() -> u64 {
    now_ms() / 1000
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// The tag every cell of one owner's device group advertises. A device chain's resource is
/// `Tag(GROUP_TAG)`, so it is valid at the gate and at revoke.list and nowhere else.
pub const GROUP_TAG: &str = "owner.devices";
/// What a device may do at the gate.
pub const ABILITY_CALL: &str = "paid-api:call";
/// What a device may do at revoke.list.
pub const ABILITY_REVOKE: &str = "devices:revoke";

/// `--name value` from the command line.
pub fn arg(name: &str) -> Option<String> {
    let a: Vec<String> = std::env::args().collect();
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1).cloned())
}

/// `--name value`, or exit with a usage line.
pub fn need(name: &str, usage: &str) -> String {
    arg(name).unwrap_or_else(|| {
        eprintln!("missing {name}\n{usage}");
        std::process::exit(2)
    })
}

/// Parse a request body as `T`, or a 400 answer.
pub fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, http::Resp> {
    serde_json::from_slice(b).map_err(|e| http::Resp::json(400, &serde_json::json!({"error": format!("bad request: {e}")})))
}
