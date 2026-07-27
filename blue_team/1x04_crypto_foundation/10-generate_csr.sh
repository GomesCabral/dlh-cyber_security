#!/bin/bash

set -euo pipefail

KEY_FILE="portal_key.pem"
CSR_FILE="portal.csr"
CONFIG_FILE="openssl.cnf"

if [ -e "$KEY_FILE" ] || [ -e "$CSR_FILE" ] || [ -e "$CONFIG_FILE" ]; then
    echo "Error: output files already exist. Remove or rename them first." >&2
    exit 1
fi

cat > "$CONFIG_FILE" <<'EOF'
[ req ]
prompt = no
distinguished_name = req_distinguished_name
req_extensions = req_ext
default_md = sha256

[ req_distinguished_name ]
C = LU
ST = Wiltz
L = Wiltz
O = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local

[ req_ext ]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = login.meddefense.local
DNS.3 = patient.meddefense.local
EOF

openssl genpkey   -algorithm EC   -pkeyopt ec_paramgen_curve:P-256   -out "$KEY_FILE"

chmod 600 "$KEY_FILE"

openssl req   -new   -sha256   -key "$KEY_FILE"   -out "$CSR_FILE"   -config "$CONFIG_FILE"

openssl req -in "$CSR_FILE" -noout -verify
openssl req -in "$CSR_FILE" -noout -subject

echo
echo "Requested extensions:"
openssl req -in "$CSR_FILE" -noout -text   | sed -n '/Requested Extensions:/,/Signature Algorithm:/p'

echo
ls -l "$KEY_FILE" "$CSR_FILE" "$CONFIG_FILE"
