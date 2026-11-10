#!/usr/bin/env python3
"""Hybrid TLS server setup (RSA certificate, X25519MLKEM768 key exchange).
Port of setup-tls-server-hybrid.sh.

Run on the TLS server VM as root. Moving files to and from the PKI VM is done
by orchestrate.py on the client machine.

  sudo ./setup_tls_server_hybrid.py csr [out-dir]         create key, CSR and extension file
                                                          (optionally copy CSR + ext to out-dir)
  sudo ./setup_tls_server_hybrid.py install-certs <dir>   install signed certs and verify them
  sudo ./setup_tls_server_hybrid.py test-server           TLS 1.3 test listener (X25519MLKEM768)

The test server is an OpenSSL TLS 1.3 listener constrained to the hybrid
X25519MLKEM768 group. It is a test harness, not an Nginx/Apache configuration.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL = os.environ.get("OPENSSL", "/usr/local/bin/openssl35")
TLS_DIR = Path(os.environ.get("TLS_DIR", "/etc/pki/tls-hybrid"))
TLS_CN = os.environ.get("TLS_CN", "tls-hybrid")
TLS_DNS = os.environ.get("TLS_DNS", "tls-hybrid")
TLS_IP = os.environ.get("TLS_IP", "192.168.205.100")
HYBRID_GROUP = os.environ.get("HYBRID_GROUP", "X25519MLKEM768")
TEST_PORT = os.environ.get("TEST_PORT", "4433")

PRIVATE_DIR = TLS_DIR / "private"
CERT_DIR = TLS_DIR / "certs"
SERVER_KEY = PRIVATE_DIR / "server.key"
SERVER_CSR = CERT_DIR / "server.csr"
SERVER_EXT = CERT_DIR / "server-ext.cnf"
SERVER_CERT = CERT_DIR / "server.crt"
FULLCHAIN = CERT_DIR / "server-fullchain.crt"
ROOT_CERT = CERT_DIR / "root-ca.crt"
INT_CERT = CERT_DIR / "intermediate-ca.crt"

SIGNED_FILES = ("server.crt", "server-fullchain.crt", "intermediate-ca.crt", "root-ca.crt")


# --- helpers ----------------------------------------------------------------
def die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def run(*cmd):
    subprocess.run([str(c) for c in cmd], check=True)


def output(*cmd):
    return subprocess.run([str(c) for c in cmd], check=True,
                          capture_output=True, text=True).stdout


def need_root():
    if os.geteuid() != 0:
        die(f"Run as root: sudo {' '.join(sys.argv)}")


def nonempty(path):
    return Path(path).is_file() and Path(path).stat().st_size > 0


def install_dir(path, mode):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


# --- checks -----------------------------------------------------------------
def require_openssl35():
    if not os.access(OPENSSL, os.X_OK):
        die(f"OpenSSL 3.5 executable not found or not executable: {OPENSSL}\n"
            "Install the openssl35 wrapper at /usr/local/bin/openssl35 on this VM.")
    result = subprocess.run([OPENSSL, "version"], capture_output=True, text=True)
    if result.returncode != 0:
        die(f"Unable to execute {OPENSSL}. Check its library path and installation.")
    version = result.stdout.strip()
    if not re.match(r"OpenSSL\s3\.5\.", version):
        die(f"OpenSSL 3.5 is required; {OPENSSL} reports: {version}")
    print(f"Using {version} ({OPENSSL})")


def check_hybrid_tls_support():
    groups = subprocess.run([OPENSSL, "list", "-tls1_3", "-tls-groups"],
                            capture_output=True, text=True).stdout
    if not re.search("X25519MLKEM768", groups, re.I):
        die(f"""The active OpenSSL library does not advertise {HYBRID_GROUP} for TLS 1.3.

Use OpenSSL 3.5.x or later with ML-KEM enabled, and make sure this is the
same OpenSSL installation used by the TLS service. Check with:
  "{OPENSSL}" version -a
  "{OPENSSL}" list -tls1_3 -tls-groups""")


def check_cert_materials():
    if not (nonempty(SERVER_KEY) and nonempty(SERVER_CERT) and nonempty(INT_CERT)):
        die(f"Certificate materials missing. Run setup first: sudo {sys.argv[0]} csr")


# --- csr steps --------------------------------------------------------------
def create_tls_dirs():
    install_dir(PRIVATE_DIR, 0o700)
    install_dir(CERT_DIR, 0o755)


def create_server_key():
    if not SERVER_KEY.is_file():
        old = os.umask(0o077)
        try:
            run(OPENSSL, "genpkey", "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:4096", "-out", SERVER_KEY)
        finally:
            os.umask(old)
    SERVER_KEY.chmod(0o600)


def create_csr():
    run(OPENSSL, "req", "-new", "-sha256",
        "-key", SERVER_KEY,
        "-out", SERVER_CSR,
        "-subj", f"/CN={TLS_CN}")


def write_server_ext():
    SERVER_EXT.write_text(
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        f"subjectAltName = DNS:{TLS_DNS}, IP:{TLS_IP}\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid,issuer\n"
    )


def copy_csr_to(out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in (SERVER_CSR, SERVER_EXT):
        shutil.copyfile(f, out_dir / f.name)
        (out_dir / f.name).chmod(0o644)


def make_csr(out_dir=None):
    check_hybrid_tls_support()
    create_tls_dirs()
    create_server_key()
    create_csr()
    write_server_ext()
    if out_dir:
        copy_csr_to(out_dir)
    print(f"CSR ready:  {SERVER_CSR}")
    print(f"Extensions: {SERVER_EXT}")


# --- install-certs steps ----------------------------------------------------
def check_signed_files(src_dir):
    for name in SIGNED_FILES:
        if not (src_dir / name).is_file():
            die(f"Missing signed file: {src_dir / name}")


def copy_signed_files(src_dir):
    for name in SIGNED_FILES:
        shutil.copyfile(src_dir / name, CERT_DIR / name)
        (CERT_DIR / name).chmod(0o644)


def verify_chain():
    run(OPENSSL, "verify", "-CAfile", ROOT_CERT, "-untrusted", INT_CERT, SERVER_CERT)


def check_key_matches_cert():
    # Confirm that the issued certificate corresponds to the local private key.
    key_pub = output(OPENSSL, "pkey", "-in", SERVER_KEY, "-pubout", "-outform", "PEM")
    cert_pub = output(OPENSSL, "x509", "-in", SERVER_CERT, "-pubkey", "-noout")
    if key_pub.strip() != cert_pub.strip():
        die("The returned certificate does not match the local server key.")


def install_certs(src_dir):
    src_dir = Path(src_dir)
    check_signed_files(src_dir)
    copy_signed_files(src_dir)
    verify_chain()
    check_key_matches_cert()
    print(f"""
Hybrid TLS server certificate materials are ready:
  Private key: {SERVER_KEY}
  Certificate: {SERVER_CERT}
  Fullchain:   {FULLCHAIN}
  Root CA:     {ROOT_CERT}

The certificate is RSA-signed. Configure your TLS server for TLS 1.3 and
{HYBRID_GROUP} separately. For a quick OpenSSL test, run:
  sudo {sys.argv[0]} test-server

This script does not modify Nginx, Apache, or another production web server.""")


# --- test-server ------------------------------------------------------------
def test_server():
    check_hybrid_tls_support()
    check_cert_materials()
    print(f"Starting TLS 1.3 test listener on port {TEST_PORT}.")
    print(f"Required key exchange group: {HYBRID_GROUP}")
    print("Connect with a client that supports this group and trusts:")
    print(f"  {ROOT_CERT}")
    print("Press Ctrl+C to stop.", flush=True)
    os.execv(OPENSSL, [OPENSSL, "s_server",
                       "-accept", TEST_PORT,
                       "-tls1_3",
                       "-groups", HYBRID_GROUP,
                       "-cert", str(SERVER_CERT),
                       "-cert_chain", str(INT_CERT),
                       "-key", str(SERVER_KEY),
                       "-www"])


# --- main -------------------------------------------------------------------
def usage(stream=sys.stdout):
    print(f"""Usage:
  sudo {sys.argv[0]} csr [out-dir]          Generate key/CSR
  sudo {sys.argv[0]} install-certs <dir>    Install signed certificates, verify chain
  sudo {sys.argv[0]} test-server            Run a TLS 1.3 test listener using {HYBRID_GROUP}

Environment:
  OPENSSL, TLS_DIR, TLS_CN, TLS_DNS, TLS_IP, HYBRID_GROUP, TEST_PORT""", file=stream)


def main(args):
    need_root()
    require_openssl35()
    mode = args[0] if args else ""
    if mode == "csr" and len(args) in (1, 2):
        make_csr(*args[1:])
    elif mode == "install-certs" and len(args) == 2:
        install_certs(args[1])
    elif mode == "test-server":
        test_server()
    elif mode in ("-h", "--help", "help"):
        usage()
    else:
        usage(sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except subprocess.CalledProcessError as e:
        die(f"Command failed: {' '.join(map(str, e.cmd))}", e.returncode)
