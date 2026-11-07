#!/usr/bin/env python3
"""Classical (RSA) TLS server certificate setup. Port of setup-tls-server.sh.

Run on the TLS server VM (192.168.205.152) as root. Moving files to and from
the PKI VM is done by orchestrate.py on the client machine.

  sudo ./setup_tls_server.py csr [out-dir]         create key, CSR and extension file
                                                   (optionally copy CSR + ext to out-dir)
  sudo ./setup_tls_server.py install-certs <dir>   install the signed certs from <dir>
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

OPENSSL = os.environ.get("OPENSSL", "openssl")
TLS_DIR = Path(os.environ.get("TLS_DIR", "/etc/pki/tls"))
TLS_CN = os.environ.get("TLS_CN", "tls")
TLS_DNS = os.environ.get("TLS_DNS", "tls")
# Address clients use to reach this TLS VM (SAN).
TLS_IP = os.environ.get("TLS_IP", "192.168.205.152")

PRIVATE_DIR = TLS_DIR / "private"
CERT_DIR = TLS_DIR / "certs"
SERVER_KEY = PRIVATE_DIR / "server.key"
SERVER_CSR = CERT_DIR / "server.csr"
SERVER_EXT = CERT_DIR / "server-ext.cnf"
SERVER_CERT = CERT_DIR / "server.crt"
FULLCHAIN = CERT_DIR / "server-fullchain.crt"
ROOT_CERT = CERT_DIR / "root-ca.crt"

SIGNED_FILES = ("server.crt", "server-fullchain.crt", "intermediate-ca.crt", "root-ca.crt")


# --- helpers ----------------------------------------------------------------
def die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


def run(*cmd):
    subprocess.run([str(c) for c in cmd], check=True)


def need_root():
    if os.geteuid() != 0:
        die(f"Run as root: sudo {' '.join(sys.argv)}")


def require_command(name):
    if shutil.which(name) is None:
        die(f"Required command not found: {name}")


# --- csr steps --------------------------------------------------------------
def create_tls_dirs():
    PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    PRIVATE_DIR.chmod(0o700)


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
    run(OPENSSL, "req", "-new",
        "-key", SERVER_KEY,
        "-out", SERVER_CSR,
        "-subj", f"/CN={TLS_CN}")


def write_server_ext():
    SERVER_EXT.write_text(
        "basicConstraints = CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        f"subjectAltName = DNS:{TLS_DNS}, IP:{TLS_IP}\n"
    )


def copy_csr_to(out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for f in (SERVER_CSR, SERVER_EXT):
        shutil.copyfile(f, out_dir / f.name)
        (out_dir / f.name).chmod(0o644)


def make_csr(out_dir=None):
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


def install_certs(src_dir):
    src_dir = Path(src_dir)
    check_signed_files(src_dir)
    copy_signed_files(src_dir)
    print(f"""PKI materials for the web server:
  Key:       {SERVER_KEY}
  Cert:      {SERVER_CERT}
  Fullchain: {FULLCHAIN}
  Root CA:   {ROOT_CERT}

Use the fullchain as the server certificate (leaf + intermediate) and the
private key as the server key. Install root-ca.crt in the client trust store.""")


# --- main -------------------------------------------------------------------
def usage(stream=sys.stdout):
    print(f"""Usage:
  sudo {sys.argv[0]} csr [out-dir]
  sudo {sys.argv[0]} install-certs <dir>""", file=stream)


def main(args):
    need_root()
    require_command(OPENSSL)
    mode = args[0] if args else ""
    if mode == "csr" and len(args) in (1, 2):
        make_csr(*args[1:])
    elif mode == "install-certs" and len(args) == 2:
        install_certs(args[1])
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
