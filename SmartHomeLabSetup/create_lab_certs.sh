#!/usr/bin/env bash
set -euo pipefail

# A2A Smart Home Security Lab - Certificate Generation
# Creates a lab CA and signed certificates for genuine and attacker agents.
# Both certificates share the same CN/SANs to simulate DNS poisoning.
# Includes all per-agent hostnames as Subject Alternative Names.

CERTS_DIR="./certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

export MSYS_NO_PATHCONV=1

echo "=== A2A Smart Home Security Lab - Certificate Generation ==="
echo ""

# --- Lab CA ---
echo "[1/4] Creating Lab CA (4096-bit RSA)..."
openssl genpkey -algorithm RSA -out lab-ca.key -pkeyopt rsa_keygen_bits:4096 2>/dev/null
openssl req -x509 -new -nodes -key lab-ca.key -sha256 -days 3650 \
  -subj "/CN=SmartHome Lab CA/O=A2A Security Research/C=MT" -out lab-ca.crt

# --- Genuine agent certificate (covers all agent hostnames) ---
cat > genuine.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = smarthome.example.com
O = SmartHome Labs
C = MT

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = smarthome.example.com
DNS.2 = thermostat.smarthome.example.com
DNS.3 = camera.smarthome.example.com
DNS.4 = doorlock.smarthome.example.com
DNS.5 = lighting.smarthome.example.com
DNS.6 = genuine-thermostat
DNS.7 = genuine-camera
DNS.8 = genuine-doorlock
DNS.9 = genuine-lighting
DNS.10 = localhost
IP.1 = 172.20.0.10
IP.2 = 172.20.0.11
IP.3 = 172.20.0.12
IP.4 = 172.20.0.13
EOF

echo "[2/4] Creating genuine agent certificate..."
openssl genpkey -algorithm RSA -out genuine.key -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -key genuine.key -config genuine.cnf -out genuine.csr
openssl x509 -req -in genuine.csr -CA lab-ca.crt -CAkey lab-ca.key \
  -CAcreateserial -out genuine.crt -days 825 -sha256 \
  -extensions v3_req -extfile genuine.cnf

# --- Attacker certificate (same hostnames for DNS poisoning) ---
cat > attacker.cnf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = smarthome.example.com
O = SmartHome Labs
C = MT

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = smarthome.example.com
DNS.2 = thermostat.smarthome.example.com
DNS.3 = camera.smarthome.example.com
DNS.4 = doorlock.smarthome.example.com
DNS.5 = lighting.smarthome.example.com
DNS.6 = attacker-relay
DNS.7 = localhost
IP.1 = 172.20.0.4
EOF

echo "[3/4] Creating attacker certificate (same CNs for DNS poisoning)..."
openssl genpkey -algorithm RSA -out attacker.key -pkeyopt rsa_keygen_bits:2048 2>/dev/null
openssl req -new -key attacker.key -config attacker.cnf -out attacker.csr
openssl x509 -req -in attacker.csr -signkey attacker.key \
  -out attacker.crt -days 825 -sha256 \
  -extensions v3_req -extfile attacker.cnf

# --- Export public key for JWS verification ---
echo "[4/4] Exporting genuine public key for JWS verification..."
openssl rsa -in genuine.key -pubout -out genuine.pub.pem 2>/dev/null

# Cleanup temporary files
rm -f *.csr *.srl *.cnf

echo ""
echo "=== Certificates Generated ==="
echo ""
ls -la
echo ""
echo "--- Genuine Certificate SANs ---"
openssl x509 -in genuine.crt -noout -subject -issuer
openssl x509 -in genuine.crt -noout -ext subjectAltName 2>/dev/null || true
echo ""
echo "--- Attacker Certificate SANs ---"
openssl x509 -in attacker.crt -noout -subject -issuer
openssl x509 -in attacker.crt -noout -ext subjectAltName 2>/dev/null || true
echo ""
echo "=== Architecture ==="
echo "  Thermostat : 172.20.0.10 (Tier 3 - Hub-class, 1.0 CPU, 256MB)"
echo "  Camera     : 172.20.0.11 (Tier 2 - Embedded,  0.5 CPU, 128MB)"
echo "  Door Lock  : 172.20.0.12 (Tier 2 - Embedded,  0.5 CPU, 128MB)"
echo "  Lighting   : 172.20.0.13 (Tier 1 - Constrained, 0.25 CPU, 128MB)"
echo "  Attacker   : 172.20.0.4  (MITM relay)"
echo "  Hub        : 172.20.0.3  (Client orchestrator)"
echo "  Dashboard  : 172.20.0.5  (Web UI)"
echo "  Ollama LLM : 172.20.0.6  (LLM inference)"
echo ""
echo "Done."
