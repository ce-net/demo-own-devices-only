#!/usr/bin/env python3
"""Holder proofs of the golden vectors, checked with ce-net-capability-verify's verify.py.

verify.py checks a chain against a root. A service must also check that the call is signed by the
chain's holder (its README, "Limits"). This does that last step for every vector with a
`holder_proof`: verify the chain, take the leaf audience, check the call signature under it.

Usage: python3 check_holders.py PATH/TO/ce-net-capability-verify golden/vectors.json
"""
import json, sys
sys.path.insert(0, sys.argv[1])
from verify import decode, verify_chain  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

failed = total = 0
for v in json.load(open(sys.argv[2]))["chains"]:
    p = v.get("holder_proof")
    if not p:
        continue
    total += 1
    revoked = {(bytes.fromhex(r["issuer"]), r["nonce"]) for r in v["revoked"]}
    leaf = verify_chain(decode(v["chain_hex"]), bytes.fromhex(v["root"]), v["now"], revoked)
    try:
        Ed25519PublicKey.from_public_bytes(leaf["audience"]).verify(bytes.fromhex(p["sig"]), bytes.fromhex(p["message_hex"]))
        got = "match"
    except Exception:
        got = "mismatch"
    ok = got == p["expect"] and leaf["audience"].hex() == v["holder"]
    failed += not ok
    who = "holder" if p["signer"] == v["holder"] else "someone else"
    print(f"{'ok  ' if ok else 'FAIL'} {v['name']:34} signed by {who:12} -> holder proof {got}")
print(f"{total - failed}/{total} holder proofs as expected")
sys.exit(1 if failed else 0)
