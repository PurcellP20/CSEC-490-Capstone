#!/usr/bin/env bash
# Run on the TLS server VM as root.
#
# Default action: create an RSA server key/CSR, have the remote hybrid CA sign
# it, retrieve the chain, and verify it.
#
# Optional test mode:
#   sudo ./setup-tls-server-hybrid.sh test-server
#
# The test server is an OpenSSL TLS 1.3 listener constrained to the hybrid
# X25519MLKEM768 group. It is a test harness, not an Nginx/Apache configuration.

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
PKI_HOST="${PKI_HOST:-192.168.193.147}"
PKI_SIGN_SCRIPT="${PKI_SIGN_SCRIPT:-/usr/local/sbin/setup-pki-hybrid.sh}"
PKI_REMOTE_IN="${PKI_REMOTE_IN:-/tmp/tls-sign-hybrid}"

TLS_DIR="${TLS_DIR:-/etc/pki/tls-hybrid}"
TLS_CN="${TLS_CN:-tls-hybrid}"
TLS_DNS="${TLS_DNS:-tls-hybrid}"
TLS_IP="${TLS_IP:-192.168.205.100}"

HYBRID_GROUP="${HYBRID_GROUP:-X25519MLKEM768}"
TEST_PORT="${TEST_PORT:-4433}"

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

check_hybrid_tls_support() {
    local version groups
    version="$("${OPENSSL}" version)"
    groups="$("${OPENSSL}" list -tls1_3 -tls-groups 2>/dev/null || true)"

    echo "Using ${version}"
    if ! grep -Eqi 'X25519MLKEM768' <<< "${groups}"; then
        cat >&2 <<EOF
The active OpenSSL library does not advertise ${HYBRID_GROUP} for TLS 1.3.

Use OpenSSL 3.5.x or later with ML-KEM enabled, and make sure this is the
same OpenSSL installation used by the TLS service. Check with:
  "${OPENSSL}" version -a
  "${OPENSSL}" list -tls1_3 -tls-groups
EOF
        exit 1
    fi
}

write_server_ext() {
    cat > "${CERT_DIR}/server-ext.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
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
        "${OPENSSL}" genpkey -algorithm RSA \
            -pkeyopt rsa_keygen_bits:4096 \
            -out "${SERVER_KEY}"
    fi
    chmod 600 "${SERVER_KEY}"

    "${OPENSSL}" req -new -sha256 \
        -key "${SERVER_KEY}" \
        -out "${SERVER_CSR}" \
        -subj "/CN=${TLS_CN}"

    write_server_ext
}

sign_on_pki() {
    local remote="${PKI_USER}@${PKI_HOST}"

    echo "Preparing signing directory on ${remote} ..."
    ssh "${remote}" "mkdir -p '${PKI_REMOTE_IN}'"

    scp "${SERVER_CSR}" "${CERT_DIR}/server-ext.cnf" \
        "${remote}:${PKI_REMOTE_IN}/"

    echo "Requesting certificate signature from hybrid CA ..."
    # -t permits sudo configurations that require a terminal.
    ssh -t "${remote}" \
        "sudo '${PKI_SIGN_SCRIPT}' sign '${PKI_REMOTE_IN}/server.csr' '${PKI_REMOTE_IN}/server-ext.cnf' '${PKI_REMOTE_IN}'"

    echo "Retrieving signed certificate chain ..."
    scp "${remote}:${PKI_REMOTE_IN}/server.crt" "${SERVER_CERT}"
    scp "${remote}:${PKI_REMOTE_IN}/server-fullchain.crt" "${FULLCHAIN}"
    scp "${remote}:${PKI_REMOTE_IN}/intermediate-ca.crt" "${INT_CERT}"
    scp "${remote}:${PKI_REMOTE_IN}/root-ca.crt" "${ROOT_CERT}"

    chmod 644 "${SERVER_CERT}" "${FULLCHAIN}" "${INT_CERT}" "${ROOT_CERT}"

    "${OPENSSL}" verify \
        -CAfile "${ROOT_CERT}" \
        -untrusted "${INT_CERT}" \
        "${SERVER_CERT}"

    # Confirm that the issued certificate corresponds to the local private key.
    local key_pub cert_pub
    key_pub="$("${OPENSSL}" pkey -in "${SERVER_KEY}" -pubout -outform PEM | "${OPENSSL}" sha256)"
    cert_pub="$("${OPENSSL}" x509 -in "${SERVER_CERT}" -pubkey -noout | "${OPENSSL}" sha256)"
    if [[ "${key_pub}" != "${cert_pub}" ]]; then
        echo "The returned certificate does not match the local server key." >&2
        exit 1
    fi
}

test_server() {
    check_hybrid_tls_support
    [[ -s "${SERVER_KEY}" && -s "${SERVER_CERT}" && -s "${INT_CERT}" ]] || {
        echo "Certificate materials missing. Run setup first: sudo $0" >&2
        exit 1
    }

    echo "Starting TLS 1.3 test listener on port ${TEST_PORT}."
    echo "Required key exchange group: ${HYBRID_GROUP}"
    echo "Connect with a client that supports this group and trusts:"
    echo "  ${ROOT_CERT}"
    echo "Press Ctrl+C to stop."
    exec "${OPENSSL}" s_server \
        -accept "${TEST_PORT}" \
        -tls1_3 \
        -groups "${HYBRID_GROUP}" \
        -cert "${SERVER_CERT}" \
        -cert_chain "${INT_CERT}" \
        -key "${SERVER_KEY}" \
        -www
}

usage() {
    cat <<EOF
Usage:
  sudo $0                 Generate key/CSR, obtain certificate, verify chain
  sudo $0 test-server     Run a TLS 1.3 test listener using ${HYBRID_GROUP}
  sudo $0 --help

Configure before running with environment variables:
  OPENSSL
  PKI_USER, PKI_HOST, PKI_SIGN_SCRIPT, PKI_REMOTE_IN
  TLS_DIR, TLS_CN, TLS_DNS, TLS_IP
  HYBRID_GROUP, TEST_PORT

The CA certificate remains RSA. Hybrid key exchange is negotiated by TLS 1.3;
it is not encoded in the X.509 server certificate.
EOF
}

main() {
    need_root "$@"
    require_openssl35

    case "${1:-setup}" in
        setup)
            require_command ssh
            require_command scp
            check_hybrid_tls_support
            generate_key_and_csr
            sign_on_pki
            cat <<EOF

Hybrid TLS server certificate materials are ready:
  Private key: ${SERVER_KEY}
  Certificate: ${SERVER_CERT}
  Fullchain:   ${FULLCHAIN}
  Root CA:     ${ROOT_CERT}

The certificate is RSA-signed. Configure your TLS server for TLS 1.3 and
${HYBRID_GROUP} separately. For a quick OpenSSL test, run:
  sudo $0 test-server

This script does not modify Nginx, Apache, or another production web server.
EOF
            ;;
        test-server)
            test_server
            ;;
        -h|--help|help)
            usage
            ;;
        *)
            usage >&2
            exit 2
            ;;
    esac
}

main "$@"
