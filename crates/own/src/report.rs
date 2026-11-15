//! Read the four devices' call logs and the revoke record; print the story and check it.

use serde_json::Value;
use std::path::Path;

struct Call {
    t1: u64,
    ok: bool,
    reason: String,
}

fn load(p: &Path) -> Result<Vec<Call>, String> {
    let s = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(s.lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|v| Call {
            t1: v["t1"].as_u64().unwrap_or(0),
            ok: v["ok"] == true,
            reason: v["reason"].as_str().unwrap_or("").to_string(),
        })
        .collect())
}

fn count(c: &[&Call]) -> (usize, usize) {
    (c.iter().filter(|x| x.ok).count(), c.iter().filter(|x| !x.ok).count())
}

pub fn run(run: &Path) -> Result<(), String> {
    let rv: Value = serde_json::from_str(&std::fs::read_to_string(run.join("revoke.json")).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let revoke_ms = rv["at_ms"].as_u64().ok_or("revoke.json: no at_ms")?;
    let mut fails: Vec<String> = Vec::new();
    let mut lines = Vec::new();
    let mut reasons = Vec::new();
    let mut first_refusal = None;
    let start = ["laptop", "phone", "desktop", "friend"]
        .iter()
        .filter_map(|d| load(&run.join(format!("logs/{d}.jsonl"))).ok()?.first().map(|c| c.t1))
        .min()
        .unwrap_or(revoke_ms);
    for (dev, key) in [("laptop", "its own"), ("phone", "its own"), ("desktop", "its own"), ("friend", "copied from phone")] {
        let calls = load(&run.join(format!("logs/{dev}.jsonl")))?;
        let before: Vec<&Call> = calls.iter().filter(|c| c.t1 < revoke_ms).collect();
        let after: Vec<&Call> = calls.iter().filter(|c| c.t1 >= revoke_ms).collect();
        let (ba, br) = count(&before);
        let (aa, ar) = count(&after);
        let after_text = if dev == "phone" && ar > 0 {
            format!("{aa} accepted, then {ar} refused")
        } else if ar == 0 {
            format!("{aa} accepted")
        } else {
            format!("{ar} refused")
        };
        let before_text = if br == 0 { format!("{ba} accepted") } else if ba == 0 { format!("{br} refused") } else { format!("{ba} accepted, {br} refused") };
        lines.push(format!("  {dev:<8} {key:<18} {before_text:<22} {after_text}"));
        if before.is_empty() || after.is_empty() {
            fails.push(format!("{dev}: no calls on one side of the revoke"));
        }
        match dev {
            "laptop" | "desktop" => {
                if br + ar > 0 {
                    fails.push(format!("{dev}: {} refused calls", br + ar));
                }
            }
            "phone" => {
                if br > 0 {
                    fails.push("phone: refused before it was revoked".into());
                }
                let fr = after.iter().position(|c| !c.ok);
                match fr {
                    None => fails.push("phone: never refused after the revoke".into()),
                    Some(i) => {
                        first_refusal = Some(after[i].t1 - revoke_ms);
                        reasons.push(format!("  phone : {}", after[i].reason));
                        if after[i..].iter().any(|c| c.ok) {
                            fails.push("phone: accepted again after its first refusal".into());
                        }
                        if !after[i].reason.contains("capability revoked") {
                            fails.push("phone: refused for another reason than revocation".into());
                        }
                    }
                }
            }
            _ => {
                if ba + aa > 0 {
                    fails.push(format!("friend: {} accepted calls with a copied key", ba + aa));
                }
                if let Some(c) = calls.first() {
                    reasons.push(format!("  friend: {}", c.reason));
                    if !calls.iter().all(|c| c.reason.contains("holder proof does not match")) {
                        fails.push("friend: refused for another reason than the holder proof".into());
                    }
                }
            }
        }
    }
    println!("Four devices call one paid API through access.gate. The phone is revoked from the laptop at +{:.2} s.", (revoke_ms - start) as f64 / 1000.0);
    println!();
    println!("  {:<8} {:<18} {:<22} {}", "device", "key file", "before revoke", "after revoke");
    for l in &lines {
        println!("{l}");
    }
    println!();
    println!("Refusal reasons, as access.gate returned them:");
    for r in &reasons {
        println!("{r}");
    }
    println!();
    match first_refusal {
        Some(ms) => println!("Revoke to the phone's first refusal: {ms} ms"),
        None => println!("Revoke to the phone's first refusal: never"),
    }
    if fails.is_empty() {
        println!("PASS: laptop, phone and desktop accepted; the copied key refused (holder proof); the revoked phone refused; laptop and desktop kept working.");
        Ok(())
    } else {
        for f in &fails {
            println!("FAIL: {f}");
        }
        Err("the story did not hold".into())
    }
}
