#!/usr/bin/env python3
"""Classical (RSA) PKI: Root CA + Intermediate CA. Port of setup-pki.sh.

Run on the PKI VM (192.168.193.147) as root:
  sudo ./setup_pki.py                                  create Root CA + Intermediate CA
  sudo ./setup_pki.py sign <csr> <extfile> [out-dir]   sign a TLS server CSR
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL = os.environ.get("OPENSSL", "openssl")
PKI_ROOT = Path(os.environ.get("PKI_ROOT", "/etc/pki"))
DAYS_ROOT = os.environ.get("DAYS_ROOT", "300")
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


def generate_rsa_key(path):
    old = os.umask(0o077)
    try:
        run(OPENSSL, "genpkey", "-algorithm", "RSA",
            "-pkeyopt", "rsa_keygen_bits:4096", "-out", path)
    finally:
        os.umask(old)


# --- init steps -------------------------------------------------------------
def create_ca_dirs():
    for d in (ROOT_DIR, INT_DIR):
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)


def create_root_key():
    if not ROOT_KEY.is_file():
        generate_rsa_key(ROOT_KEY)


def create_root_cert():
    if not ROOT_CERT.is_file():
        run(OPENSSL, "req", "-x509", "-new", "-nodes",
            "-key", ROOT_KEY,
            "-sha512", "-days", DAYS_ROOT,
            "-subj", "/CN=Root-CA",
            "-out", ROOT_CERT)


def create_intermediate_key():
    if not INT_KEY.is_file():
        generate_rsa_key(INT_KEY)


def write_intermediate_ext():
    INT_EXT.write_text(INTERMEDIATE_EXT)


def create_intermediate_cert():
    if INT_CERT.is_file():
        return
    run(OPENSSL, "req", "-new",
        "-key", INT_KEY,
        "-out", INT_CSR,
        "-subj", "/CN=Intermediate-CA")
    run(OPENSSL, "x509", "-req",
        "-in", INT_CSR,
        "-CA", ROOT_CERT,
        "-CAkey", ROOT_KEY,
        "-CAcreateserial",
        "-out", INT_CERT,
        "-days", DAYS_INT,
        "-sha256",
        "-extfile", INT_EXT)


def set_ca_permissions():
    ROOT_KEY.chmod(0o600)
    INT_KEY.chmod(0o600)
    ROOT_CERT.chmod(0o644)
    INT_CERT.chmod(0o644)


def init_ca():
    create_ca_dirs()
    create_root_key()
    create_root_cert()
    create_intermediate_key()
    write_intermediate_ext()
    create_intermediate_cert()
    set_ca_permissions()

    print("PKI ready:")
    print(f"  Root CA:         {ROOT_CERT}")
    print(f"  Intermediate CA: {INT_CERT}")
    print()
    print("Sign a TLS CSR with:")
    print(f"  sudo {sys.argv[0]} sign /path/to/server.csr /path/to/server-ext.cnf")


# --- sign steps -------------------------------------------------------------
def check_ca_initialized():
    if not INT_CERT.is_file():
        die(f"CAs are not initialized. Run: sudo {sys.argv[0]}")


def check_sign_inputs(csr, ext):
    if not csr.is_file() or not ext.is_file():
        die("CSR or extension file not found.")


def sign_csr(csr, ext, server_cert):
    run(OPENSSL, "x509", "-req",
        "-in", csr,
        "-CA", INT_CERT,
        "-CAkey", INT_KEY,
        "-CAcreateserial",
        "-out", server_cert,
        "-days", DAYS_SERVER,
        "-sha256",
        "-extfile", ext)


def build_fullchain(server_cert, fullchain):
    fullchain.write_bytes(server_cert.read_bytes() + INT_CERT.read_bytes())


def verify_server_cert(server_cert):
    run(OPENSSL, "verify", "-CAfile", ROOT_CERT, "-untrusted", INT_CERT, server_cert)


def copy_files(files, out_dir):
    for f in files:
        shutil.copyfile(f, out_dir / f.name)


def sign_server(csr, ext, out_dir=None):
    csr, ext = Path(csr), Path(ext)
    out_dir = Path(out_dir) if out_dir else INT_DIR
    server_csr = INT_DIR / "server.csr"
    server_ext = INT_DIR / "server-ext.cnf"
    server_cert = INT_DIR / "server.crt"
    fullchain = INT_DIR / "server-fullchain.crt"

    check_ca_initialized()
    check_sign_inputs(csr, ext)
    out_dir.mkdir(parents=True, exist_ok=True)
    if csr.resolve() != server_csr.resolve():
        shutil.copyfile(csr, server_csr)
    if ext.resolve() != server_ext.resolve():
        shutil.copyfile(ext, server_ext)

    sign_csr(server_csr, server_ext, server_cert)
    build_fullchain(server_cert, fullchain)
    verify_server_cert(server_cert)

    if out_dir.resolve() != INT_DIR.resolve():
        copy_files([server_cert, fullchain, INT_CERT, ROOT_CERT], out_dir)

    server_cert.chmod(0o644)
    fullchain.chmod(0o644)

    print("Signed certificate artifacts:")
    print(f"  {server_cert}")
    print(f"  {fullchain}")
    print(f"  {ROOT_CERT}")


# --- main -------------------------------------------------------------------
def usage(stream=sys.stdout):
    print(f"""Usage:
  sudo {sys.argv[0]}                 Initialize Root + Intermediate CAs
  sudo {sys.argv[0]} sign <csr> <extfile> [out-dir]""", file=stream)


def main(args):
    need_root()
    mode = args[0] if args else "init"
    if mode == "init":
        init_ca()
    elif mode == "sign" and len(args) in (3, 4):
        sign_server(*args[1:])
    elif mode in ("-h", "--help", "help"):
        usage()
    else:
        usage(sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except subprocess.CalledProcessError as e:
        die(f"Command failed: {' '.join(map(str, e.cmd))}", e.returncode)
