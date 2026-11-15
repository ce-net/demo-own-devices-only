#!/usr/bin/env bash
# The whole story on one machine: four local processes are four devices.
#   laptop, phone, desktop: enrolled with a pairing code, each holds a chain bound to its own key
#   friend: has a copy of the phone's key file, but its own device secret
# Then the laptop revokes the phone. Prints the result and writes it to run/four-devices.txt.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
DEPS=$ROOT/deps
RUN=$ROOT/run
SIM_REV=0dd3be88460ae717b1ad3ac31bd698a0574c87f8      # ce-net-local-dev-sim
VERIFY_REV=9dc71170174234f89fc18f1162835fa4065418c0   # ce-net-capability-verify

fetch() { # name rev
  if [ ! -d "$DEPS/$1/.git" ]; then git clone -q "https://github.com/ce-net/$1" "$DEPS/$1"; fi
  git -C "$DEPS/$1" -c advice.detachedHead=false checkout -q "$2"
}
mkdir -p "$DEPS"
fetch ce-net-local-dev-sim "$SIM_REV"
fetch ce-net-capability-verify "$VERIFY_REV"

echo "== build"
cargo build --release --locked --quiet
BIN=${CARGO_TARGET_DIR:-$ROOT/target}/release

rm -rf "$RUN"; mkdir -p "$RUN"/{logs,owner,enroll,gate,list,laptop,phone,desktop,friend}
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

wait_for() { # file pattern
  for _ in $(seq 1 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done
  echo "timed out waiting for $2 in $1" >&2; cat "$1" >&2; exit 1
}

echo "== directory (ce-net-local-dev-sim) and cells"
python3 "$DEPS/ce-net-local-dev-sim/cenet_mock.py" 0 > "$RUN/dir.log" 2>&1 & PIDS+=($!)
wait_for "$RUN/dir.log" "cenet-mock on"
export CE_DIR=$(grep -o 'http://[^ ]*/mcp' "$RUN/dir.log")

"$BIN/own" owner init --home "$RUN/owner" > /dev/null
ENROLL_ID=$("$BIN/device-enroll" id --home "$RUN/enroll")
"$BIN/own" owner grant --home "$RUN/owner" --to "$ENROLL_ID" --out "$RUN/enroll/grant.chain"
"$BIN/revoke-list" id --home "$RUN/list" > "$RUN/list/revoke-list.pub"

"$BIN/paid-api" > "$RUN/paid-api.log" 2>&1 & PIDS+=($!)
wait_for "$RUN/paid-api.log" "http://"
UPSTREAM=$(head -1 "$RUN/paid-api.log")
"$BIN/device-enroll" serve --home "$RUN/enroll" --grant "$RUN/enroll/grant.chain" > "$RUN/enroll.log" 2>&1 & PIDS+=($!)
"$BIN/revoke-list" serve --home "$RUN/list" --owner-pub "$RUN/owner/owner.pub" > "$RUN/list.log" 2>&1 & PIDS+=($!)
wait_for "$RUN/list.log" "revoke.list .* on"
"$BIN/access-gate" serve --home "$RUN/gate" --owner-pub "$RUN/owner/owner.pub" \
  --list-pub "$RUN/list/revoke-list.pub" --upstream "$UPSTREAM" > "$RUN/gate.log" 2>&1 & PIDS+=($!)
wait_for "$RUN/enroll.log" "device.enroll .* on"
wait_for "$RUN/gate.log" "access.gate .* on"
sed -n 1p "$RUN/enroll.log"; sed -n 1p "$RUN/list.log"; sed -n 1p "$RUN/gate.log" | sed 's/ -> .*/ -> paid API/'

echo "== enroll laptop, phone, desktop (one pairing code each, from the owner)"
for d in laptop phone desktop; do
  CODE=$("$BIN/own" owner pair --home "$RUN/owner")
  echo -n "code $CODE -> "
  "$BIN/own" device enroll --home "$RUN/$d" --name "$d" --code "$CODE"
done
echo "== friend gets a copy of the phone's key file (not the phone's device secret)"
cp "$RUN/phone/device.key" "$RUN/friend/device.key"
echo "== reusing a burned pairing code"
"$BIN/own" device enroll --home "$RUN/friend" --name friend --code "$CODE" 2>&1 | sed 's/^own: /refused: /' || true

echo "== four devices call the paid API through access.gate every 100 ms"
for d in laptop phone desktop friend; do
  "$BIN/own" device loop --home "$RUN/$d" --log "$RUN/logs/$d.jsonl" --stop "$RUN/stop" --every-ms 100 & PIDS+=($!)
done
sleep 2
echo "== the phone is lost: revoke it from the laptop"
"$BIN/own" device revoke --home "$RUN/laptop" --name phone | tee "$RUN/revoke.json"
sleep 3
touch "$RUN/stop"; sleep 0.5

echo "== result"
"$BIN/own" report --run "$RUN" | tee "$RUN/four-devices.txt"

echo "== golden vectors, checked by ce-net-capability-verify"
PY=python3
if ! python3 -c 'import cryptography' 2>/dev/null; then
  python3 -m venv "$DEPS/.venv"; "$DEPS/.venv/bin/pip" -q install -r "$DEPS/ce-net-capability-verify/requirements.txt"
  PY=$DEPS/.venv/bin/python3
fi
(cd "$DEPS/ce-net-capability-verify" && "$PY" test_vectors.py "$ROOT/golden/vectors.json") | tee -a "$RUN/four-devices.txt"
"$PY" golden/check_holders.py "$DEPS/ce-net-capability-verify" golden/vectors.json | tee -a "$RUN/four-devices.txt"
