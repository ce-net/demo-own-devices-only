//! Publish and find cells in a ce-net directory over MCP JSON-RPC (`agent_join`, `app_publish`,
//! `apps_search`). Locally this is ce-net-local-dev-sim; the same calls work against the live
//! directory. The directory only says where a cell is. Trust comes from pinned keys, never from it.

use serde_json::{Value, json};

fn tool(dir: &str, bearer: Option<&str>, name: &str, args: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}});
    let auth = bearer.map(|k| format!("Bearer {k}"));
    let mut headers = vec![("Content-Type", "application/json")];
    if let Some(a) = auth.as_deref() {
        headers.push(("Authorization", a));
    }
    let (_, b) = crate::http::request("POST", dir, &headers, &serde_json::to_vec(&body).unwrap())?;
    let v: Value = serde_json::from_slice(&b).map_err(|e| format!("directory answered non-json: {e}"))?;
    let r = &v["result"];
    if r["isError"].as_bool() == Some(true) {
        return Err(format!("directory: {}", r["content"][0]["text"].as_str().unwrap_or("error")));
    }
    Ok(r["structuredContent"].clone())
}

/// Join the directory as `name` and list the cell at `url`.
pub fn publish(dir: &str, name: &str, url: &str, what: &str) -> Result<(), String> {
    let j = tool(dir, None, "agent_join", json!({"name": name, "about": what}))?;
    let key = j["key"].as_str().ok_or("directory: no key")?.to_string();
    tool(dir, Some(&key), "app_publish", json!({"name": name, "url": url, "what": what, "kind": "http"}))?;
    Ok(())
}

/// Find the URL of the cell listed under exactly `name`.
pub fn find(dir: &str, name: &str) -> Result<String, String> {
    let j = tool(dir, None, "apps_search", json!({"q": name}))?;
    j["apps"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["name"] == name))
        .and_then(|x| x["url"].as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("directory: no cell named {name}"))
}

/// The directory URL: `$CE_DIR`, else the local sim's default.
pub fn default_dir() -> String {
    std::env::var("CE_DIR").unwrap_or_else(|_| "http://127.0.0.1:7878/mcp".into())
}
