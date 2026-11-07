#!/usr/bin/env bash
# Post-quantum TLS server VM.
# Uses an ML-DSA-65 server certificate and pure ML-KEM-768 TLS 1.3
# key establishment. This is a PQ-only lab configuration, not a public-web
# compatibility configuration.
#
# Run:
#   sudo -E ./setup-tls-server-pq.sh
#   sudo ./setup-tls-server-pq.sh test-server

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

PKI_USER="${PKI_USER:-owen}"
PKI_HOST="${PKI_HOST:-192.168.205.151}"
PKI_SIGN_SCRIPT="${PKI_SIGN_SCRIPT:-/usr/local/sbin/setup-pki-pq.sh}"
PKI_REMOTE_IN="${PKI_REMOTE_IN:-/tmp/tls-sign-pq}"

TLS_DIR="${TLS_DIR:-/etc/pki/tls-pq}"
TLS_CN="${TLS_CN:-tls-pq}"
TLS_DNS="${TLS_DNS:-tls-pq}"
TLS_IP="${TLS_IP:-192.168.205.152}"

PQ_GROUP="${PQ_GROUP:-MLKEM768}"
TEST_PORT="${TEST_PORT:-4443}"

PRIVATE_DIR="${TLS_DIR}/private"
CERT_DIR="${TLS_DIR}/certs"
SERVER_KEY="${PRIVATE_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"
FULLCHAIN="${CERT_DIR}/server-fullchain.crt"
ROOT_CERT="${CERT_DIR}/root-ca.crt"
INT_CERT="${CERT_DIR}/intermediate-ca.crt"

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "Run as root: sudo $0 $*" >&2
        exit 1
    fi
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Required command not found: $1" >&2
        exit 1
    }
}

check_pq_tls_support() {
    local sigs groups
    echo "OpenSSL: $("${OPENSSL}" version)"
    sigs="$("${OPENSSL}" list -signature-algorithms 2>/dev/null || true)"
    groups="$("${OPENSSL}" list -tls1_3 -tls-groups 2>/dev/null || true)"

    grep -Eqi 'ML-DSA-65|MLDSA65' <<< "${sigs}" || {
        echo "ML-DSA-65 is unavailable in the active OpenSSL build." >&2
        exit 1
    }
    grep -Eqi "${PQ_GROUP}" <<< "${groups}" || {
        echo "${PQ_GROUP} TLS group is unavailable in the active OpenSSL build." >&2
        echo "Check: ${OPENSSL} list -tls1_3 -tls-groups" >&2
        exit 1
    }
}

write_server_ext() {
    cat > "${CERT_DIR}/server-ext.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:${TLS_DNS}, IP:${TLS_IP}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
}

generate_key_and_csr() {
    install -d -m 700 "${PRIVATE_DIR}"
    install -d -m 755 "${CERT_DIR}"

    if [[ ! -f "${SERVER_KEY}" ]]; then
        umask 077
        "${OPENSSL}" genpkey -algorithm ML-DSA-65 -out "${SERVER_KEY}"
    fi
    chmod 600 "${SERVER_KEY}"

    "${OPENSSL}" req -new \
        -key "${SERVER_KEY}" \
        -out "${SERVER_CSR}" \
        -subj "/CN=${TLS_CN}"

    write_server_ext
}

sign_on_pki() {
    local remote="${PKI_USER}@${PKI_HOST}"

    ssh "${remote}" "mkdir -p '${PKI_REMOTE_IN}'"
    scp "${SERVER_CSR}" "${CERT_DIR}/server-ext.cnf" \
        "${remote}:${PKI_REMOTE_IN}/"

    ssh -t "${remote}" \
        "sudo '${PKI_SIGN_SCRIPT}' sign '${PKI_REMOTE_IN}/server.csr' '${PKI_REMOTE_IN}/server-ext.cnf' '${PKI_REMOTE_IN}'"

    scp "${remote}:${PKI_REMOTE_IN}/server.crt" "${SERVER_CERT}"
    scp "${remote}:${PKI_REMOTE_IN}/server-fullchain.crt" "${FULLCHAIN}"
    scp "${remote}:${PKI_REMOTE_IN}/intermediate-ca.crt" "${INT_CERT}"
    scp "${remote}:${PKI_REMOTE_IN}/root-ca.crt" "${ROOT_CERT}"

    chmod 644 "${SERVER_CERT}" "${FULLCHAIN}" "${INT_CERT}" "${ROOT_CERT}"

    "${OPENSSL}" verify \
        -CAfile "${ROOT_CERT}" \
        -untrusted "${INT_CERT}" \
        "${SERVER_CERT}"

    local key_pub cert_pub
    key_pub="$("${OPENSSL}" pkey -in "${SERVER_KEY}" -pubout -outform PEM | "${OPENSSL}" sha256)"
    cert_pub="$("${OPENSSL}" x509 -in "${SERVER_CERT}" -pubkey -noout | "${OPENSSL}" sha256)"
    [[ "${key_pub}" == "${cert_pub}" ]] || {
        echo "Returned certificate does not match local private key." >&2
        exit 1
    }
}

test_server() {
    check_pq_tls_support
    [[ -s "${SERVER_KEY}" && -s "${SERVER_CERT}" && -s "${INT_CERT}" ]] || {
        echo "Certificate materials missing. Run setup first: sudo $0" >&2
        exit 1
    }

    echo "Starting TLS 1.3 test listener on port ${TEST_PORT}."
    echo "Required pure-PQ key exchange group: ${PQ_GROUP}"
    echo "Press Ctrl+C to stop."
    exec "${OPENSSL}" s_server \
        -accept "${TEST_PORT}" \
        -tls1_3 \
        -groups "${PQ_GROUP}" \
        -cert "${SERVER_CERT}" \
        -cert_chain "${INT_CERT}" \
        -key "${SERVER_KEY}" \
        -www
}

usage() {
    cat <<EOF
Usage:
  sudo -E $0             Generate ML-DSA key/CSR, obtain cert and verify chain
  sudo $0 test-server    Run TLS 1.3 listener constrained to ${PQ_GROUP}

Environment:
  OPENSSL        OpenSSL 3.5 executable (default: /usr/local/bin/openssl35)
  PKI_USER, PKI_HOST, PKI_SIGN_SCRIPT, PKI_REMOTE_IN
  TLS_DIR, TLS_CN, TLS_DNS, TLS_IP
  PQ_GROUP (default: MLKEM768), TEST_PORT (default: 4443)
EOF
}

main() {
    need_root "$@"
    require_openssl35
    case "${1:-setup}" in
        setup)
            require_command ssh
            require_command scp
            check_pq_tls_support
            generate_key_and_csr
            sign_on_pki
            cat <<EOF

Post-quantum TLS materials are ready:
  ML-DSA-65 private key: ${SERVER_KEY}
  ML-DSA-65 certificate: ${SERVER_CERT}
  Fullchain:             ${FULLCHAIN}
  Root CA:               ${ROOT_CERT}

For the lab TLS test, run:
  sudo $0 test-server

The TLS test uses TLS 1.3 with pure ML-KEM-768 key establishment.
EOF
            ;;
        test-server) test_server ;;
        -h|--help|help) usage ;;
        *) usage >&2; exit 2 ;;
    esac
}

main "$@"
