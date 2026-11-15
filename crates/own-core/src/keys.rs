//! Key material on disk.
//!
//! A device home holds two files:
//! - `device.secret`: the device's Ed25519 secret (hex). Made on the device, never sent anywhere.
//! - `device.key`: the key file: the holder-bound chain the enroll cell issued, plus labels. It is
//!   not secret on its own: copying it to another device gives that device nothing, because every
//!   call must be signed by the secret behind the chain's leaf.

use ce_net_proto::Identity;
use std::path::Path;

/// 32 random bytes from the operating system.
pub fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom").expect("/dev/urandom");
    std::io::Read::read_exact(&mut f, &mut b).expect("read /dev/urandom");
    b
}

/// A random u64 (chain nonces, request nonces).
pub fn random_u64() -> u64 {
    let b = random32();
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

/// Load `path` as a hex Ed25519 secret, or create it (mode 0600) if it does not exist.
pub fn load_or_create_secret(path: &Path) -> Result<Identity, String> {
    if path.exists() {
        return load_secret(path);
    }
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let sk = random32();
    write_private(path, hex::encode(sk).as_bytes())?;
    Ok(Identity::from_secret_bytes(&sk))
}

pub fn load_secret(path: &Path) -> Result<Identity, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let b = hex::decode(s.trim()).map_err(|_| format!("{}: not hex", path.display()))?;
    let sk: [u8; 32] = b.try_into().map_err(|_| format!("{}: not 32 bytes", path.display()))?;
    Ok(Identity::from_secret_bytes(&sk))
}

pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        std::io::Write::write_all(&mut f, data).map_err(|e| e.to_string())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data).map_err(|e| e.to_string())
    }
}

/// Read a hex public key (a NodeId) from a file.
pub fn read_pub(path: &Path) -> Result<ce_net_proto::NodeId, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    ce_net_proto::identity::node_id_from_hex(s.trim()).map_err(|e| e.0)
}
