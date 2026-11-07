#!/usr/bin/env bash
# Hybrid TLS PKI: classical RSA certificate hierarchy.
# Run on the PKI/CA VM:
#   sudo ./setup-pki-hybrid.sh
#   sudo ./setup-pki-hybrid.sh sign <server.csr> <server-ext.cnf> [out-dir]
#
# "Hybrid" here refers to TLS key exchange (X25519 + ML-KEM-768), not
# hybrid certificate signatures. The CA and server certificates remain RSA.

set -euo pipefail

OPENSSL="${OPENSSL:-/usr/local/bin/openssl35}"

require_openssl35() {
    if [[ ! -x "${OPENSSL}" ]]; then
        echo "OpenSSL 3.5 executable not found or not executable: ${OPENSSL}" >&2
        echo "Install the openssl35 wrapper at /usr/local/bin/openssl35 on this VM." >&2
        exit 1
    fi

    local version
    version="$("${OPENSSL}" version 2>/dev/null)" || {
        echo "Unable to execute ${OPENSSL}. Check its library path and installation." >&2
        exit 1
    }
    if [[ ! "${version}" =~ ^OpenSSL[[:space:]]3\.5\. ]]; then
        echo "OpenSSL 3.5 is required; ${OPENSSL} reports: ${version}" >&2
        exit 1
    fi
    echo "Using ${version} (${OPENSSL})"
}

PKI_ROOT="${PKI_ROOT:-/etc/pki-hybrid}"
ROOT_DIR="${PKI_ROOT}/root-ca"
INT_DIR="${PKI_ROOT}/intermediate-ca"

DAYS_ROOT="${DAYS_ROOT:-3000}"
DAYS_INT="${DAYS_INT:-1825}"
DAYS_SERVER="${DAYS_SERVER:-397}"

ROOT_KEY="${ROOT_DIR}/root-ca.key"
ROOT_CERT="${ROOT_DIR}/root-ca.crt"
INT_KEY="${INT_DIR}/intermediate-ca.key"
INT_CERT="${INT_DIR}/intermediate-ca.crt"

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "Run as root: sudo $0 $*" >&2
        exit 1
    fi
}

require_openssl() {
    require_openssl35
}

write_intermediate_ext() {
    cat > "${INT_DIR}/intermediate-ext.cnf" <<'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
}

init_ca() {
    install -d -m 700 "${ROOT_DIR}" "${INT_DIR}"

    if [[ ! -f "${ROOT_KEY}" ]]; then
        umask 077
        "${OPENSSL}" genpkey -algorithm RSA \
            -pkeyopt rsa_keygen_bits:4096 \
            -out "${ROOT_KEY}"
    fi

    if [[ ! -f "${ROOT_CERT}" ]]; then
        "${OPENSSL}" req -x509 -new -sha512 \
            -key "${ROOT_KEY}" \
            -days "${DAYS_ROOT}" \
            -subj "/CN=Hybrid-Experiment-Root-CA" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -addext "subjectKeyIdentifier=hash" \
            -out "${ROOT_CERT}"
    fi

    write_intermediate_ext

    if [[ ! -f "${INT_KEY}" ]]; then
        umask 077
        "${OPENSSL}" genpkey -algorithm RSA \
            -pkeyopt rsa_keygen_bits:4096 \
            -out "${INT_KEY}"
    fi

    if [[ ! -f "${INT_CERT}" ]]; then
        "${OPENSSL}" req -new -sha256 \
            -key "${INT_KEY}" \
            -out "${INT_DIR}/intermediate-ca.csr" \
            -subj "/CN=Hybrid-Experiment-Intermediate-CA"

        "${OPENSSL}" x509 -req \
            -in "${INT_DIR}/intermediate-ca.csr" \
            -CA "${ROOT_CERT}" \
            -CAkey "${ROOT_KEY}" \
            -CAcreateserial \
            -out "${INT_CERT}" \
            -days "${DAYS_INT}" \
            -sha256 \
            -extfile "${INT_DIR}/intermediate-ext.cnf"
    fi

    chmod 600 "${ROOT_KEY}" "${INT_KEY}"
    chmod 644 "${ROOT_CERT}" "${INT_CERT}"

    "${OPENSSL}" verify -CAfile "${ROOT_CERT}" "${INT_CERT}"

    cat <<EOF
Hybrid TLS PKI initialized (RSA certificate hierarchy):
  Root CA certificate:         ${ROOT_CERT}
  Intermediate CA certificate:${INT_CERT}

This CA signs RSA server certificates. Hybrid key exchange is negotiated
separately by TLS 1.3 endpoints using X25519MLKEM768.
EOF
}

sign_server() {
    local csr="${1:-}"
    local ext="${2:-}"
    local out_dir="${3:-${INT_DIR}}"
    local server_cert="${out_dir}/server.crt"

    if [[ -z "${csr}" || -z "${ext}" ]]; then
        echo "Usage: sudo $0 sign <server.csr> <server-ext.cnf> [out-dir]" >&2
        exit 2
    fi
    if [[ ! -s "${ROOT_CERT}" || ! -s "${INT_CERT}" || ! -s "${INT_KEY}" ]]; then
        echo "CA is not initialized. Run: sudo $0" >&2
        exit 1
    fi
    if [[ ! -s "${csr}" || ! -s "${ext}" ]]; then
        echo "CSR or extension file is missing or empty." >&2
        exit 1
    fi

    install -d -m 700 "${out_dir}"

    # Ensure the submitted CSR is parseable before issuing a certificate.
    "${OPENSSL}" req -in "${csr}" -noout -verify

    "${OPENSSL}" x509 -req \
        -in "${csr}" \
        -CA "${INT_CERT}" \
        -CAkey "${INT_KEY}" \
        -CAcreateserial \
        -out "${server_cert}" \
        -days "${DAYS_SERVER}" \
        -sha256 \
        -extfile "${ext}"

    cat "${server_cert}" "${INT_CERT}" > "${out_dir}/server-fullchain.crt"

    "${OPENSSL}" verify \
        -CAfile "${ROOT_CERT}" \
        -untrusted "${INT_CERT}" \
        "${server_cert}"

    cp -f "${INT_CERT}" "${ROOT_CERT}" "${out_dir}/"
    chmod 644 "${server_cert}" "${out_dir}/server-fullchain.crt" \
        "${out_dir}/intermediate-ca.crt" "${out_dir}/root-ca.crt"

    echo "Signed hybrid-experiment server certificate:"
    echo "  Leaf:      ${server_cert}"
    echo "  Fullchain: ${out_dir}/server-fullchain.crt"
    echo "  Root CA:   ${out_dir}/root-ca.crt"
}

usage() {
    cat <<EOF
Usage:
  sudo $0
  sudo $0 sign <server.csr> <server-ext.cnf> [out-dir]

Environment:
  OPENSSL        OpenSSL 3.5 executable (default: /usr/local/bin/openssl35)
  OPENSSL        OpenSSL 3.5 executable (default: /usr/local/bin/openssl35)
  PKI_ROOT       CA storage root (default: /etc/pki-hybrid)
  DAYS_ROOT      Root certificate lifetime in days (default: 3000)
  DAYS_INT       Intermediate certificate lifetime (default: 1825)
  DAYS_SERVER    Server certificate lifetime (default: 397)
EOF
}

need_root "$@"
require_openssl

case "${1:-init}" in
    init) init_ca ;;
    sign)
        shift
        sign_server "$@"
        ;;
    -h|--help|help) usage ;;
    *)
        usage >&2
        exit 2
        ;;
esac
