#!/usr/bin/env bash
# Generates throwaway PKI + served keys for gokeyless interop testing.
set -euo pipefail
out="${1:-$(dirname "$0")/fixtures}"
rm -rf "$out" && mkdir -p "$out/keys" "$out/certs"
cd "$out"
export MSYS_NO_PATHCONV=1  # keep "/CN=..." intact under Git Bash

openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -subj "/CN=Keyless Interop CA" -days 30 -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,digitalSignature"

issue() { # name eku san
  openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$1-key.pem"
  openssl req -new -key "$1-key.pem" -subj "/CN=$1" -out "$1.csr"
  printf "basicConstraints=CA:FALSE\nextendedKeyUsage=%s\n%s" "$2" "${3:+subjectAltName=$3}" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
  rm "$1.csr" "$1.ext"
}
issue server serverAuth "DNS:localhost,IP:127.0.0.1"
issue client clientAuth ""

# Served keys in each on-disk format the servers must parse.
openssl genrsa -traditional -out keys/rsa.key 2048 2>/dev/null           # PKCS#1
openssl ecparam -name prime256v1 -genkey -out keys/p256.key               # SEC1 (+ EC PARAMETERS block)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out keys/p384.key  # PKCS#8
for k in rsa p256 p384; do
  # Leaf certificates for the served keys, as a TLS terminator would hold them.
  openssl req -new -key "keys/$k.key" -subj "/CN=$k.example.test" -out "$k.csr"
  printf "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s.example.test\n" "$k" > "$k.ext"
  openssl x509 -req -in "$k.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 30 -extfile "$k.ext" -out "certs/$k.crt" 2>/dev/null
  rm "$k.csr" "$k.ext"
done
echo "fixtures written to $out"
