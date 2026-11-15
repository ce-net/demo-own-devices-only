# Shared with my devices, nobody else's

Leif pays for an API. He wants his laptop, his phone and his desktop to use it, and nobody else, even
someone who gets hold of a key file. When he loses the phone, he wants it cut off in seconds without
touching the other two.

This demo does that with three reusable cells in front of the paid API, and four local processes as
four devices:

1. Leif enrolls the laptop, the phone and the desktop with a one-time pairing code each. Each device
   makes its own secret key and gets a capability chain bound to that key.
2. All three call the paid API through the gate. Accepted.
3. The phone's key file is copied to a fourth device, a friend's. Refused: the call is not signed by the
   key the chain was issued to.
4. Leif revokes the phone from the laptop. The phone is refused within a fraction of a second (208 ms in the recorded run). The laptop and the
   desktop keep working.

## The recorded run

[`proof/four-devices.txt`](proof/four-devices.txt) is the output of `./scripts/four-devices.sh`. Each device calls every
100 ms; the phone is revoked about 2 s in.

```
  device   key file           before revoke          after revoke
  laptop   its own            17 accepted            26 accepted
  phone    its own            18 accepted            1 accepted, then 25 refused
  desktop  its own            18 accepted            26 accepted
  friend   copied from phone  19 refused             29 refused

Refusal reasons, as access.gate returned them:
  phone : link 1: capability revoked: device 'phone' was revoked at 1794766476664 (list version 1)
  friend: holder proof does not match: the request is not signed by the chain's holder e3c3b1093af2f9a7

Revoke to the phone's first refusal: 208 ms
```

The same run then checks the golden vectors with the independent Python verifier
[ce-net-capability-verify](https://github.com/ce-net/ce-net-capability-verify): `11/11 vectors pass` and
`5/5 holder proofs as expected`.

## Run it in under 5 minutes

You need git, Rust 1.85 or newer, and Python 3.9 or newer. Linux or macOS.

```sh
git clone https://github.com/ce-net/demo-demo-own-devices-only
cd demo-demo-own-devices-only
./scripts/four-devices.sh
```

The script fetches its two other public dependencies into `deps/` (pinned commits):
[ce-net-local-dev-sim](https://github.com/ce-net/ce-net-local-dev-sim), the local directory the cells register in, and
ce-net-capability-verify. Cargo fetches [ce-net-proto](https://github.com/ce-net/ce-net-proto), the capability chain
library. The first build takes about a minute. If the `cryptography` Python package is missing, the script installs it
in `deps/.venv`. It exits non-zero if any part of the story does not hold.

`cargo test --release` runs the gate's other refusals (no revocation list yet, a stale list, a forged list, an older
list, a replayed call, a call signed for another gate) and checks that `golden/vectors.json` is reproduced byte for
byte.

## The cells

| Cell | Crate | Job |
|---|---|---|
| `device.enroll@1` | [`device-enroll`](crates/device-enroll) | The owner signs a request for a pairing code (`XXXX-XXXX`, one use, 2 minutes). A device sends the code, a name, its public key and a signature by that key. The cell burns the code and delegates a link to that key: `paid-api:call` and `devices:revoke`, 30 days, a fresh nonce. It holds one link from the owner, never the owner's secret |
| `access.gate@1` | [`access-gate`](crates/access-gate) | Fronts any HTTP upstream (`--upstream URL`, `--action ABILITY`). A call passes only if the gate holds a fresh revocation list, the request is signed by the chain's leaf holder, and ce-net-proto `authorize` accepts the chain for the gate's action. Then it forwards `METHOD /path` upstream with `X-Ce-Holder` |
| `revoke.list@1` | [`revoke-list`](crates/revoke-list) | An enrolled device whose chain grants `devices:revoke` names another device's link `(issuer, nonce)`. A revoked device cannot revoke anyone. Gates poll the list, which is signed fresh on every read |

Also in the repo: [`paid-api`](crates/paid-api), the example upstream (no auth of its own, reachable only through the
gate); [`own`](crates/own), the owner's and the devices' command line; [`own-core`](crates/own-core), the shared HTTP,
key file, signed request and directory code; [`golden`](crates/golden), the vector generator.

### The chain a device holds

```
link 0  owner  -> device.enroll   paid-api:call, devices:revoke   on Tag(owner.devices)   365 days
link 1  enroll -> this device     paid-api:call, devices:revoke   on Tag(owner.devices)   30 days, nonce n
```

The gate and revoke.list advertise the tag `owner.devices`, so the chain is valid there and nowhere else. Each link
can only narrow its parent; ce-net-proto checks that on every call.

### What a device signs

Every call is a JSON envelope `{chain, ts, nonce, what, body, sig}`. `sig` is the device's Ed25519 signature over:

```
ce-own-devices-call-v1
to <gate key>
chain <sha256 of the chain hex>
ts <unix ms>
nonce <random u64>
what GET /v1/quote
body <sha256 of the body>
```

The gate does not take a claimed sender. It takes the chain's leaf audience, the key the chain was issued to, and checks
the signature under that key. The friend's device signs with its own secret, so the check fails. The timestamp must be
within 30 s of the gate's clock, and a `(holder, nonce)` pair is accepted once.

### How revocation reaches the gate

The laptop asks device.enroll for the phone's link `(issuer, nonce)` and sends a signed revoke request to revoke.list.
revoke.list checks the laptop's chain for `devices:revoke`, adds the entry and bumps the list version. The gate fetches
the list every 200 ms and adopts it only if it is signed by the pinned revoke.list key, its version and issue time do not
go backwards, and it was issued at most 3 s ago. Without such a list the gate refuses every call, so cutting it off from
revoke.list cannot keep a revoked phone working.

### Where cells find each other

Each cell lists itself in a ce-net directory (`app_publish`) and devices find it by name (`apps_search`). Here that is
ce-net-local-dev-sim; the same two MCP calls work against the live directory. The directory only says where a cell is.
Trust comes from the pinned keys: the owner's public key and the revoke.list key.

## Golden vectors

[`golden/vectors.json`](golden/vectors.json) holds 11 holder-bound chains from fixed keys, in the ce-net-capability-verify
`vectors.json` format, plus a `holder_proof` (a signed call and whether it is the holder's) on five of them:

| Vector | Expected |
|---|---|
| `laptop`, `phone`, `desktop` | valid, holder proof matches |
| `phone-key-copied-to-friend` | the chain is valid; the call is signed by the friend, holder proof does not match |
| `phone-revoked` | `link 1: capability revoked` |
| `laptop-after-phone-revoked`, `desktop-after-phone-revoked` | valid |
| `phone-after-30-days` | `link 1: capability has expired` |
| `enroll-widens-ability` | `link 1: abilities exceed the parent` |
| `phone-passes-on-longer-life` | `link 2: caveats are broader than the parent` |
| `other-owner` | `capability chain does not root at an accepted authority` |

Check them yourself without this repo's code:

```sh
git clone https://github.com/ce-net/ce-net-capability-verify deps/ce-net-capability-verify
(cd deps/ce-net-capability-verify && python3 test_vectors.py ../../golden/vectors.json)
python3 golden/check_holders.py deps/ce-net-capability-verify golden/vectors.json
```

## Limits

- One machine, loopback HTTP. The devices are separate processes with separate secrets; they are not separate
  hardware, and the device secret is a file (`device.secret`, mode 0600), not a secure enclave.
- The time to the first refusal depends on the gate's 200 ms poll and the device's 100 ms call interval. A push from
  revoke.list would make it shorter; the 3 s freshness limit is what bounds it when the push is lost.
- State lives in memory. Restarting device.enroll forgets the enrolled devices; restarting revoke.list empties the list,
  and a gate that had a newer version refuses the restarted list until its own process restarts.
- `GET /devices` on device.enroll lists names, public keys and nonces to anyone who can reach it. None of those is
  secret, but a real deployment would put it behind the same holder proof.

## License

Apache-2.0. See [LICENSE](LICENSE). Author: Leif Rydenfalk.
