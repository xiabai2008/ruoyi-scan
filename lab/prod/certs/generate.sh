#!/usr/bin/env sh
# Generate a self-signed certificate for the lab (idempotent).
# Called by `make cert`; can also be run directly: sh certs/generate.sh
#
# The key is intentionally untrusted and lab-only. It is written next to this
# script and mounted read-only into both nginx containers.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CRT="$DIR/server.crt"
KEY="$DIR/server.key"
CNF="$DIR/openssl.cnf"

if [ -s "$CRT" ] && [ -s "$KEY" ]; then
    echo "[cert] reusing $CRT"
    exit 0
fi

# Native Windows OpenSSL does not understand MSYS-style /d/... paths. Work
# with relative filenames from inside the cert directory instead.
cd "$DIR"
trap 'rm -f openssl.cnf' EXIT INT TERM

if ! command -v openssl >/dev/null 2>&1; then
    echo "[cert] ERROR: openssl not found in PATH." >&2
    echo "[cert] Install openssl (Git for Windows ships it) or generate the pair elsewhere:" >&2
    echo "[cert]   docker run --rm -v \"$DIR:/certs\" alpine/openssl req -x509 -nodes -newkey rsa:2048 \\" >&2
    echo "[cert]     -days 825 -keyout /certs/server.key -out /certs/server.crt \\" >&2
    echo "[cert]     -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'" >&2
    exit 1
fi

cat >openssl.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no

[dn]
C  = CN
ST = Lab
L  = Lab
O  = RuoYi-Scan Lab
OU = Security Testing
CN = localhost

[v3]
subjectAltName = DNS:localhost, DNS:ruoyi-lab.local, IP:127.0.0.1
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF

umask 077
openssl req -x509 -nodes -newkey rsa:2048 -days 825 -sha256 \
    -keyout server.key -out server.crt -config openssl.cnf

chmod 600 server.key 2>/dev/null || true
chmod 644 server.crt 2>/dev/null || true
rm -f openssl.cnf

echo "[cert] wrote $CRT (CN=localhost, SAN=localhost/127.0.0.1, valid 825 days)"
echo "[cert] browsers/curl will warn: this is a self-signed lab certificate"
