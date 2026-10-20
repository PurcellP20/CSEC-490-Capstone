#!/usr/bin/env bash
# Run on the TLS server VM as root.
# Creates the server key, CSR, and extension file, has the PKI VM sign it,
# and copies the certificate materials back. Web server setup is left to you.
#
# Requires: openssl, scp/ssh to the PKI VM, and setup-pki.sh already
# initialized there (copy it to PKI_SIGN_SCRIPT, default /usr/local/sbin/setup-pki.sh).
#
# Edit the variables below before the first run.

set -euo pipefail

PKI_USER="${PKI_USER:-user}"
PKI_HOST="${PKI_HOST:-192.168.1.10}"
PKI_SIGN_SCRIPT="${PKI_SIGN_SCRIPT:-/usr/local/sbin/setup-pki.sh}"
PKI_REMOTE_IN="${PKI_REMOTE_IN:-/tmp/tls-sign}"

TLS_DIR="${TLS_DIR:-/etc/pki/tls}"
TLS_CN="${TLS_CN:-tls}"
TLS_DNS="${TLS_DNS:-tls}"
# Address clients will use to reach THIS server (SAN). This is not the PKI VM IP
# unless the TLS VM really has that address.
TLS_IP="${TLS_IP:-192.168.1.20}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
  fi
}

write_server_ext() {
  cat > "${TLS_DIR}/certs/server-ext.cnf" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${TLS_DNS}, IP:${TLS_IP}
EOF
}

generate_key_and_csr() {
  mkdir -p "${TLS_DIR}/private" "${TLS_DIR}/certs"
  chmod 700 "${TLS_DIR}/private"

  umask 077
  if [[ ! -f "${TLS_DIR}/private/server.key" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
      -out "${TLS_DIR}/private/server.key"
  fi
  umask 022
  chmod 600 "${TLS_DIR}/private/server.key"

  openssl req -new \
    -key "${TLS_DIR}/private/server.key" \
    -out "${TLS_DIR}/certs/server.csr" \
    -subj "/CN=${TLS_CN}"

  write_server_ext
}

sign_on_pki() {
  echo "Copying CSR to PKI VM ${PKI_USER}@${PKI_HOST} ..."
  ssh "${PKI_USER}@${PKI_HOST}" "mkdir -p '${PKI_REMOTE_IN}'"
  scp \
    "${TLS_DIR}/certs/server.csr" \
    "${TLS_DIR}/certs/server-ext.cnf" \
    "${PKI_USER}@${PKI_HOST}:${PKI_REMOTE_IN}/"

  echo "Signing CSR on PKI VM ..."
  ssh -t "${PKI_USER}@${PKI_HOST}" \
    "sudo '${PKI_SIGN_SCRIPT}' sign '${PKI_REMOTE_IN}/server.csr' '${PKI_REMOTE_IN}/server-ext.cnf' '${PKI_REMOTE_IN}'"

  echo "Copying signed chain and Root CA back ..."
  scp "${PKI_USER}@${PKI_HOST}:${PKI_REMOTE_IN}/server.crt" \
      "${TLS_DIR}/certs/server.crt"
  scp "${PKI_USER}@${PKI_HOST}:${PKI_REMOTE_IN}/server-fullchain.crt" \
      "${TLS_DIR}/certs/server-fullchain.crt"
  scp "${PKI_USER}@${PKI_HOST}:${PKI_REMOTE_IN}/intermediate-ca.crt" \
      "${TLS_DIR}/certs/intermediate-ca.crt"
  scp "${PKI_USER}@${PKI_HOST}:${PKI_REMOTE_IN}/root-ca.crt" \
      "${TLS_DIR}/certs/root-ca.crt"

  chmod 644 \
    "${TLS_DIR}/certs/server.crt" \
    "${TLS_DIR}/certs/server-fullchain.crt" \
    "${TLS_DIR}/certs/intermediate-ca.crt" \
    "${TLS_DIR}/certs/root-ca.crt"
}

need_root
command -v openssl >/dev/null
command -v ssh >/dev/null
command -v scp >/dev/null

generate_key_and_csr
sign_on_pki

cat <<EOF
PKI materials for the web server:
  Key:       ${TLS_DIR}/private/server.key
  Cert:      ${TLS_DIR}/certs/server.crt
  Fullchain: ${TLS_DIR}/certs/server-fullchain.crt
  Root CA:   ${TLS_DIR}/certs/root-ca.crt

Use the fullchain as the server certificate (leaf + intermediate) and the
private key as the server key. Install root-ca.crt in the client trust store.
EOF
