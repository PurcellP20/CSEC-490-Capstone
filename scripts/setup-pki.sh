#!/usr/bin/env bash
# Run on the PKI VM as root (or via sudo).
#   sudo ./setup-pki.sh              # create Root CA + Intermediate CA
#   sudo ./setup-pki.sh sign <csr> <extfile> [out-dir]
#
# The TLS VM script calls the "sign" mode over SSH after copying the CSR.

set -euo pipefail

PKI_ROOT="${PKI_ROOT:-/etc/pki}"
ROOT_DIR="${PKI_ROOT}/root-ca"
INT_DIR="${PKI_ROOT}/intermediate-ca"
DAYS_ROOT="${DAYS_ROOT:-300}"
DAYS_INT="${DAYS_INT:-1825}"
DAYS_SERVER="${DAYS_SERVER:-397}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo $0 $*" >&2
    exit 1
  fi
}

write_intermediate_ext() {
  cat > "${INT_DIR}/intermediate-ext.cnf" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
EOF
}

init_ca() {
  mkdir -p "${ROOT_DIR}" "${INT_DIR}"
  chmod 700 "${ROOT_DIR}" "${INT_DIR}"

  umask 077
  if [[ ! -f "${ROOT_DIR}/root-ca.key" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
      -out "${ROOT_DIR}/root-ca.key"
  fi
  umask 022

  if [[ ! -f "${ROOT_DIR}/root-ca.crt" ]]; then
    openssl req -x509 -new -nodes \
      -key "${ROOT_DIR}/root-ca.key" \
      -sha512 -days "${DAYS_ROOT}" \
      -subj "/CN=Root-CA" \
      -out "${ROOT_DIR}/root-ca.crt"
  fi

  umask 077
  if [[ ! -f "${INT_DIR}/intermediate-ca.key" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
      -out "${INT_DIR}/intermediate-ca.key"
  fi
  umask 022

  write_intermediate_ext

  if [[ ! -f "${INT_DIR}/intermediate-ca.crt" ]]; then
    openssl req -new \
      -key "${INT_DIR}/intermediate-ca.key" \
      -out "${INT_DIR}/intermediate-ca.csr" \
      -subj "/CN=Intermediate-CA"

    # Command list had "-CA createserial"; the correct flag is -CAcreateserial.
    openssl x509 -req \
      -in "${INT_DIR}/intermediate-ca.csr" \
      -CA "${ROOT_DIR}/root-ca.crt" \
      -CAkey "${ROOT_DIR}/root-ca.key" \
      -CAcreateserial \
      -out "${INT_DIR}/intermediate-ca.crt" \
      -days "${DAYS_INT}" \
      -sha256 \
      -extfile "${INT_DIR}/intermediate-ext.cnf"
  fi

  chmod 600 "${ROOT_DIR}/root-ca.key" "${INT_DIR}/intermediate-ca.key"
  chmod 644 "${ROOT_DIR}/root-ca.crt" "${INT_DIR}/intermediate-ca.crt"

  echo "PKI ready:"
  echo "  Root CA:         ${ROOT_DIR}/root-ca.crt"
  echo "  Intermediate CA: ${INT_DIR}/intermediate-ca.crt"
  echo
  echo "Sign a TLS CSR with:"
  echo "  sudo $0 sign /path/to/server.csr /path/to/server-ext.cnf"
}

sign_server() {
  local csr="${1:-}"
  local ext="${2:-}"
  local out_dir="${3:-${INT_DIR}}"

  if [[ -z "${csr}" || -z "${ext}" ]]; then
    echo "Usage: sudo $0 sign <server.csr> <server-ext.cnf> [out-dir]" >&2
    exit 1
  fi
  if [[ ! -f "${INT_DIR}/intermediate-ca.crt" ]]; then
    echo "CAs are not initialized. Run: sudo $0" >&2
    exit 1
  fi
  if [[ ! -f "${csr}" || ! -f "${ext}" ]]; then
    echo "CSR or extension file not found." >&2
    exit 1
  fi

  mkdir -p "${out_dir}"
  cp -f "${csr}" "${INT_DIR}/server.csr"
  cp -f "${ext}" "${INT_DIR}/server-ext.cnf"

  openssl x509 -req \
    -in "${INT_DIR}/server.csr" \
    -CA "${INT_DIR}/intermediate-ca.crt" \
    -CAkey "${INT_DIR}/intermediate-ca.key" \
    -CAcreateserial \
    -out "${INT_DIR}/server.crt" \
    -days "${DAYS_SERVER}" \
    -sha256 \
    -extfile "${INT_DIR}/server-ext.cnf"

  cat "${INT_DIR}/server.crt" "${INT_DIR}/intermediate-ca.crt" \
    > "${INT_DIR}/server-fullchain.crt"

  openssl verify \
    -CAfile "${ROOT_DIR}/root-ca.crt" \
    -untrusted "${INT_DIR}/intermediate-ca.crt" \
    "${INT_DIR}/server.crt"

  if [[ "${out_dir}" != "${INT_DIR}" ]]; then
    cp -f \
      "${INT_DIR}/server.crt" \
      "${INT_DIR}/server-fullchain.crt" \
      "${INT_DIR}/intermediate-ca.crt" \
      "${ROOT_DIR}/root-ca.crt" \
      "${out_dir}/"
  fi

  chmod 644 \
    "${INT_DIR}/server.crt" \
    "${INT_DIR}/server-fullchain.crt"

  echo "Signed certificate artifacts:"
  echo "  ${INT_DIR}/server.crt"
  echo "  ${INT_DIR}/server-fullchain.crt"
  echo "  ${ROOT_DIR}/root-ca.crt"
}

usage() {
  cat <<EOF
Usage:
  sudo $0                 Initialize Root + Intermediate CAs
  sudo $0 sign <csr> <extfile> [out-dir]
EOF
}

need_root "$@"
case "${1:-init}" in
  init) init_ca ;;
  sign)
    shift
    sign_server "$@"
    ;;
  -h|--help|help) usage ;;
  *)
    usage >&2
    exit 1
    ;;
esac
