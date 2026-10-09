#!/usr/bin/env bash
# Cross-tests this implementation against cloudflare/gokeyless:
#   1. gokeyless-cli-tester (Go client)  -> keyless-server (Rust)
#   2. keyless-check (Rust client/rustls) -> gokeyless (Go server)
#   3. keyless-check (Rust client/rustls) -> keyless-server (Rust)
# Requires go, openssl and a gokeyless checkout (default: reference/gokeyless).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
gokeyless="${GOKEYLESS_SRC:-$root/reference/gokeyless}"
work="$root/target/interop"
exe=""; [[ "${OS:-}" == "Windows_NT" ]] && exe=".exe"
rust_port=24070 go_port=24071

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

"$root/interop/gen-fixtures.sh" "$work" >/dev/null 2>&1
(cd "$gokeyless" && go build -o "$root/target/go/" ./cmd/gokeyless ./cmd/gokeyless-cli-tester)
cargo build -q --release --manifest-path "$root/Cargo.toml" -p keyless-server --bin keyless-server
cargo build -q --release --manifest-path "$root/Cargo.toml" -p keyless-client --example keyless-check

wpath() { if command -v cygpath >/dev/null; then cygpath -m "$1"; else echo "$1"; fi; }
cat > "$work/gokeyless.yaml" <<EOF
auth_cert: $(wpath "$work/server.pem")
auth_key: $(wpath "$work/server-key.pem")
cloudflare_ca_cert: $(wpath "$work/ca.pem")
port: $go_port
metrics_port: $((go_port + 1))
private_key_stores:
  - dir: $(wpath "$work/keys")
EOF

"$root/target/release/keyless-server$exe" --listen "127.0.0.1:$rust_port" \
  --auth-cert "$work/server.pem" --auth-key "$work/server-key.pem" \
  --cloudflare-ca-cert "$work/ca.pem" --private-key-dirs "$work/keys" >"$work/rust-server.log" 2>&1 &
pids+=($!)
"$root/target/go/gokeyless$exe" --config-file "$work/gokeyless.yaml" >"$work/go-server.log" 2>&1 &
pids+=($!)
sleep 2

echo "== Go client -> Rust server"
"$root/target/go/gokeyless-cli-tester$exe" -cert "$work/client.pem" -key "$work/client-key.pem" \
  -ca-file "$work/ca.pem" -keyserver "localhost:$rust_port" -cert-directory "$work/certs/" \
  -testlen 2s -workers 8 >"$work/go-client-results.json" 2>"$work/go-client.log"
"$(command -v python3 || command -v python)" - "$work/go-client-results.json" <<'EOF'
import json, sys
from collections import defaultdict
tests = json.load(open(sys.argv[1]))["tests"]
# keyless-server deliberately drops legacy ops (MD5SHA1, SHA-1, SHA-224,
# ECDSA with a hash not matching the curve): each test must either fully
# pass or be uniformly rejected with "bad opcode".
passed, rejected, broken = defaultdict(set), 0, []
for name, t in tests.items():
    ok, bad = t["results"]["success"]["count"], t["results"]["failure"]["count"]
    ski, _, hash_ = name.rpartition(".") if name != "ping" else ("ping", "", "ping")
    if ok and not bad:
        passed[ski].add(hash_)
    elif bad and not ok and set(t["errors"]) == {"keyless: bad opcode"}:
        rejected += 1
    else:
        broken.append(f"{name}: {ok} ok, {bad} failed, {t['errors']}")
# Fixtures: one RSA key (SHA-256/384/512) and two EC keys (one matching hash each).
shapes = sorted(len(h) for ski, h in passed.items() if ski != "ping")
if shapes != [1, 1, 3] or "ping" not in passed:
    broken.append(f"unexpected passing set: {dict(passed)}")
total = sum(t["results"]["success"]["count"] for t in tests.values())
print(f"{len(tests)} tests: {sum(map(len, passed.values()))} passed ({total} operations), "
      f"{rejected} legacy ops rejected as bad opcode")
for line in broken:
    print("UNEXPECTED:", line)
sys.exit(1 if broken else 0)
EOF

for target in "Go server:$go_port" "Rust server:$rust_port"; do
  echo "== Rust client (rustls) -> ${target%%:*}"
  "$root/target/release/examples/keyless-check$exe" "127.0.0.1:${target##*:}" localhost \
    "$work/ca.pem" "$work/client.pem" "$work/client-key.pem" "$work/certs"
done
echo "== interop OK"
