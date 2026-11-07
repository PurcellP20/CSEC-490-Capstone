#!/usr/bin/env python3
"""Post-quantum PKI CA (ML-DSA-65 certificate hierarchy). Port of setup-pki-pq.sh.

Run on the PKI CA VM (192.168.205.151) as root:
  sudo ./setup_pki_pq.py
  sudo ./setup_pki_pq.py sign <server.csr> <server-ext.cnf> [out-dir]

Uses ML-DSA-65 for Root, Intermediate and server certificate signatures.
"""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL = os.environ.get("OPENSSL", "/usr/local/bin/openssl35")
PKI_ROOT = Path(os.environ.get("PKI_ROOT", "/etc/pki-pq"))
DAYS_ROOT = os.environ.get("DAYS_ROOT", "3000")
DAYS_INT = os.environ.get("DAYS_INT", "1825")
DAYS_SERVER = os.environ.get("DAYS_SERVER", "397")

ROOT_DIR = PKI_ROOT / "root-ca"
INT_DIR = PKI_ROOT / "intermediate-ca"
ROOT_KEY = ROOT_DIR / "root-ca.key"
ROOT_CERT = ROOT_DIR / "root-ca.crt"
INT_KEY = INT_DIR / "intermediate-ca.key"
INT_CERT = INT_DIR / "intermediate-ca.crt"
INT_CSR = INT_DIR / "intermediate-ca.csr"
INT_EXT = INT_DIR / "intermediate-ext.cnf"

INTERMEDIATE_EXT = """\
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
"""


# --- helpers ----------------------------------------------------------------
def die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def run(*cmd):
    subprocess.run([str(c) for c in cmd], check=True)


def need_root():
    if os.geteuid() != 0:
        die(f"Run as root: sudo {' '.join(sys.argv)}")


def nonempty(path):
    return Path(path).is_file() and Path(path).stat().st_size > 0


def install_dir(path, mode):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def generate_mldsa_key(path):
    old = os.umask(0o077)
    try:
        run(OPENSSL, "genpkey", "-algorithm", "ML-DSA-65", "-out", path)
    finally:
        os.umask(old)


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


def require_pq_support():
    sigs = subprocess.run([OPENSSL, "list", "-signature-algorithms"],
                          capture_output=True, text=True).stdout
    groups = subprocess.run([OPENSSL, "list", "-tls1_3", "-tls-groups"],
                            capture_output=True, text=True).stdout
    if not re.search("ML-DSA-65|MLDSA65", sigs, re.I):
        die("ML-DSA-65 is not available in this OpenSSL build.\n"
            "Use OpenSSL 3.5.x or later with ML-DSA enabled.")
    if not re.search("MLKEM768", groups, re.I):
        die("MLKEM768 TLS 1.3 group is not available in this OpenSSL build.\n"
            "Use OpenSSL 3.5.x or later with ML-KEM enabled.")


# --- init steps -------------------------------------------------------------
def create_ca_dirs():
    install_dir(ROOT_DIR, 0o700)
    install_dir(INT_DIR, 0o700)


def create_root_key():
    if not ROOT_KEY.is_file():
        generate_mldsa_key(ROOT_KEY)


def create_root_cert():
    if not ROOT_CERT.is_file():
        run(OPENSSL, "req", "-x509", "-new",
            "-key", ROOT_KEY,
            "-days", DAYS_ROOT,
            "-subj", "/CN=Post-Quantum-Root-CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-out", ROOT_CERT)


def write_intermediate_ext():
    INT_EXT.write_text(INTERMEDIATE_EXT)


def create_intermediate_key():
    if not INT_KEY.is_file():
        generate_mldsa_key(INT_KEY)


def create_intermediate_cert():
    if INT_CERT.is_file():
        return
    run(OPENSSL, "req", "-new",
        "-key", INT_KEY,
        "-out", INT_CSR,
        "-subj", "/CN=Post-Quantum-Intermediate-CA")
    # Do not supply -sha256/-sha512: ML-DSA performs its own signing.
    run(OPENSSL, "x509", "-req",
        "-in", INT_CSR,
        "-CA", ROOT_CERT,
        "-CAkey", ROOT_KEY,
        "-CAcreateserial",
        "-out", INT_CERT,
        "-days", DAYS_INT,
        "-extfile", INT_EXT)


def set_ca_permissions():
    ROOT_KEY.chmod(0o600)
    INT_KEY.chmod(0o600)
    ROOT_CERT.chmod(0o644)
    INT_CERT.chmod(0o644)


def verify_intermediate_cert():
    run(OPENSSL, "verify", "-CAfile", ROOT_CERT, INT_CERT)


def init_ca():
    create_ca_dirs()
    create_root_key()
    create_root_cert()
    write_intermediate_ext()
    create_intermediate_key()
    create_intermediate_cert()
    set_ca_permissions()
    verify_intermediate_cert()

    print(f"""Post-quantum PKI initialized:
  Root CA key:          {ROOT_KEY}
  Root CA certificate:  {ROOT_CERT}
  Intermediate key:     {INT_KEY}
  Intermediate cert:    {INT_CERT}

Certificate signature algorithm: ML-DSA-65""")


# --- sign steps -------------------------------------------------------------
def check_ca_initialized():
    if not (nonempty(ROOT_CERT) and nonempty(INT_CERT) and nonempty(INT_KEY)):
        die(f"CA is not initialized. Run: sudo {sys.argv[0]}")


def check_sign_inputs(csr, ext):
    if not (nonempty(csr) and nonempty(ext)):
        die("CSR or extension file is missing or empty.")


def verify_csr(csr):
    run(OPENSSL, "req", "-in", csr, "-noout", "-verify")


def sign_csr(csr, ext, server_cert):
    # ML-DSA signing: intentionally no digest option.
    run(OPENSSL, "x509", "-req",
        "-in", csr,
        "-CA", INT_CERT,
        "-CAkey", INT_KEY,
        "-CAcreateserial",
        "-out", server_cert,
        "-days", DAYS_SERVER,
        "-extfile", ext)


def build_fullchain(server_cert, fullchain):
    fullchain.write_bytes(server_cert.read_bytes() + INT_CERT.read_bytes())


def verify_server_cert(server_cert):
    run(OPENSSL, "verify", "-CAfile", ROOT_CERT, "-untrusted", INT_CERT, server_cert)


def copy_ca_certs(out_dir):
    shutil.copyfile(INT_CERT, out_dir / "intermediate-ca.crt")
    shutil.copyfile(ROOT_CERT, out_dir / "root-ca.crt")


def sign_server(csr, ext, out_dir=None):
    csr, ext = Path(csr), Path(ext)
    out_dir = Path(out_dir) if out_dir else INT_DIR
    server_cert = out_dir / "server.crt"
    fullchain = out_dir / "server-fullchain.crt"

    check_ca_initialized()
    check_sign_inputs(csr, ext)
    install_dir(out_dir, 0o700)
    verify_csr(csr)
    sign_csr(csr, ext, server_cert)
    build_fullchain(server_cert, fullchain)
    verify_server_cert(server_cert)
    copy_ca_certs(out_dir)
    for f in ("server.crt", "server-fullchain.crt", "intermediate-ca.crt", "root-ca.crt"):
        (out_dir / f).chmod(0o644)

    print("Signed post-quantum server certificate:")
    print(f"  Leaf:      {server_cert}")
    print(f"  Fullchain: {fullchain}")
    print(f"  Root CA:   {out_dir / 'root-ca.crt'}")


# --- main -------------------------------------------------------------------
def usage(stream=sys.stdout):
    print(f"""Usage:
  sudo {sys.argv[0]}
  sudo {sys.argv[0]} sign <server.csr> <server-ext.cnf> [out-dir]

Environment:
  OPENSSL        OpenSSL 3.5 executable (default: /usr/local/bin/openssl35)
  PKI_ROOT       CA storage root (default: /etc/pki-pq)
  DAYS_ROOT      Root certificate lifetime (default: 3000 days)
  DAYS_INT       Intermediate lifetime (default: 1825 days)
  DAYS_SERVER    Server certificate lifetime (default: 397 days)""", file=stream)


def main(args):
    need_root()
    require_openssl35()
    require_pq_support()
    mode = args[0] if args else "init"
    if mode == "init":
        init_ca()
    elif mode == "sign" and len(args) in (3, 4):
        sign_server(*args[1:])
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
