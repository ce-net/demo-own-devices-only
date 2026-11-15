//! A small HTTP/1.1 server and client over std TCP. One request per connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

const MAX_BODY: usize = 1 << 20;

pub struct Req {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

pub struct Resp {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(status: u16, v: &serde_json::Value) -> Resp {
        Resp { status, body: serde_json::to_vec(v).unwrap_or_default() }
    }
}

pub type Handler = Arc<dyn Fn(Req) -> Resp + Send + Sync>;

/// Bind 127.0.0.1 on `port` (0 = any free port) and return the listener and its URL.
pub fn bind(port: u16) -> std::io::Result<(TcpListener, String)> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let url = format!("http://127.0.0.1:{}", l.local_addr()?.port());
    Ok((l, url))
}

/// Serve forever, one thread per connection.
pub fn serve(l: TcpListener, h: Handler) {
    for s in l.incoming().flatten() {
        let h = h.clone();
        std::thread::spawn(move || {
            let _ = handle(s, &h);
        });
    }
}

fn read_head(r: &mut BufReader<TcpStream>) -> std::io::Result<(String, usize)> {
    let mut first = String::new();
    r.read_line(&mut first)?;
    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    Ok((first, len))
}

fn handle(s: TcpStream, h: &Handler) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let (first, len) = read_head(&mut r)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let resp = if len > MAX_BODY {
        Resp::json(413, &serde_json::json!({"error": "body too large"}))
    } else {
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        h(Req { method, path, body })
    };
    let reason = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    };
    let mut w = s;
    write!(
        w,
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        reason,
        resp.body.len()
    )?;
    w.write_all(&resp.body)?;
    w.flush()
}

/// One request to `url` (`http://host:port/path`). Returns the status and body.
pub fn request(method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("only http:// urls: {url}"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let s = TcpStream::connect(host).map_err(|e| format!("connect {host}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    w.write_all(head.as_bytes()).map_err(|e| e.to_string())?;
    w.write_all(body).map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let (first, len) = read_head(&mut r).map_err(|e| e.to_string())?;
    let status: u16 = first.split_whitespace().nth(1).and_then(|x| x.parse().ok()).ok_or("bad response line")?;
    let mut out = vec![0u8; len.min(MAX_BODY)];
    r.read_exact(&mut out).map_err(|e| e.to_string())?;
    Ok((status, out))
}

/// POST a JSON value and parse the JSON answer.
pub fn post_json(url: &str, v: &serde_json::Value) -> Result<(u16, serde_json::Value), String> {
    let (st, b) = request("POST", url, &[("Content-Type", "application/json")], &serde_json::to_vec(v).unwrap_or_default())?;
    let j = serde_json::from_slice(&b).map_err(|e| format!("bad json from {url}: {e}"))?;
    Ok((st, j))
}

/// GET and parse the JSON answer.
pub fn get_json(url: &str) -> Result<(u16, serde_json::Value), String> {
    let (st, b) = request("GET", url, &[], &[])?;
    let j = serde_json::from_slice(&b).map_err(|e| format!("bad json from {url}: {e}"))?;
    Ok((st, j))
}
