#!/usr/bin/env python3
"""Post-quantum TLS server setup (ML-DSA-65 certificate, ML-KEM-768 key exchange).
Port of setup-tls-server-pq.sh.

Run on the TLS server VM as root. Moving files to and from the PKI VM is done
by orchestrate.py on the client machine. This is a PQ-only lab configuration,
not a public-web compatibility configuration.

  sudo ./setup_tls_server_pq.py csr [out-dir]         create ML-DSA key, CSR and extension file
                                                      (optionally copy CSR + ext to out-dir)
  sudo ./setup_tls_server_pq.py install-certs <dir>   install signed certs and verify them
  sudo ./setup_tls_server_pq.py test-server           TLS 1.3 listener constrained to PQ_GROUP
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL = os.environ.get("OPENSSL", "/usr/local/bin/openssl35")
TLS_DIR = Path(os.environ.get("TLS_DIR", "/etc/pki/tls-pq"))
TLS_CN = os.environ.get("TLS_CN", "tls-pq")
TLS_DNS = os.environ.get("TLS_DNS", "tls-pq")
TLS_IP = os.environ.get("TLS_IP", "192.168.205.100")
PQ_GROUP = os.environ.get("PQ_GROUP", "MLKEM768")
TEST_PORT = os.environ.get("TEST_PORT", "4443")

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


def check_pq_tls_support():
    sigs = subprocess.run([OPENSSL, "list", "-signature-algorithms"],
                          capture_output=True, text=True).stdout
    groups = subprocess.run([OPENSSL, "list", "-tls1_3", "-tls-groups"],
                            capture_output=True, text=True).stdout
    if not re.search("ML-DSA-65|MLDSA65", sigs, re.I):
        die("ML-DSA-65 is unavailable in the active OpenSSL build.")
    if not re.search(PQ_GROUP, groups, re.I):
        die(f"{PQ_GROUP} TLS group is unavailable in the active OpenSSL build.\n"
            f"Check: {OPENSSL} list -tls1_3 -tls-groups")


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
            run(OPENSSL, "genpkey", "-algorithm", "ML-DSA-65", "-out", SERVER_KEY)
        finally:
            os.umask(old)
    SERVER_KEY.chmod(0o600)


def create_csr():
    run(OPENSSL, "req", "-new",
        "-key", SERVER_KEY,
        "-out", SERVER_CSR,
        "-subj", f"/CN={TLS_CN}")


def write_server_ext():
    SERVER_EXT.write_text(
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
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
    check_pq_tls_support()
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
    key_pub = output(OPENSSL, "pkey", "-in", SERVER_KEY, "-pubout", "-outform", "PEM")
    cert_pub = output(OPENSSL, "x509", "-in", SERVER_CERT, "-pubkey", "-noout")
    if key_pub.strip() != cert_pub.strip():
        die("Returned certificate does not match local private key.")


def install_certs(src_dir):
    src_dir = Path(src_dir)
    check_signed_files(src_dir)
    copy_signed_files(src_dir)
    verify_chain()
    check_key_matches_cert()
    print(f"""
Post-quantum TLS materials are ready:
  ML-DSA-65 private key: {SERVER_KEY}
  ML-DSA-65 certificate: {SERVER_CERT}
  Fullchain:             {FULLCHAIN}
  Root CA:               {ROOT_CERT}

For the lab TLS test, run:
  sudo {sys.argv[0]} test-server

The TLS test uses TLS 1.3 with pure ML-KEM-768 key establishment.""")


# --- test-server ------------------------------------------------------------
def test_server():
    check_pq_tls_support()
    check_cert_materials()
    print(f"Starting TLS 1.3 test listener on port {TEST_PORT}.")
    print(f"Required pure-PQ key exchange group: {PQ_GROUP}")
    print("Press Ctrl+C to stop.", flush=True)
    os.execv(OPENSSL, [OPENSSL, "s_server",
                       "-accept", TEST_PORT,
                       "-tls1_3",
                       "-groups", PQ_GROUP,
                       "-cert", str(SERVER_CERT),
                       "-cert_chain", str(INT_CERT),
                       "-key", str(SERVER_KEY),
                       "-www"])


# --- main -------------------------------------------------------------------
def usage(stream=sys.stdout):
    print(f"""Usage:
  sudo {sys.argv[0]} csr [out-dir]          Generate ML-DSA key/CSR
  sudo {sys.argv[0]} install-certs <dir>    Install signed certificates, verify chain
  sudo {sys.argv[0]} test-server            Run TLS 1.3 listener constrained to {PQ_GROUP}

Environment:
  OPENSSL, TLS_DIR, TLS_CN, TLS_DNS, TLS_IP
  PQ_GROUP (default: MLKEM768), TEST_PORT (default: 4443)""", file=stream)


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
