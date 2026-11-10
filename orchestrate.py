#!/usr/bin/env python3
"""Run the 2-VM PKI setups from one client machine over SSH.

  python orchestrate.py check                      check SSH, python3 and sudo on both VMs
  python orchestrate.py install-openssl            build the latest OpenSSL 3.5.x on both VMs and
                                                   install it as /usr/local/bin/openssl35
  python orchestrate.py deploy -v pq               copy the scripts to both VMs
  python orchestrate.py run -v pq                  deploy + full CA / TLS setup
  python orchestrate.py start-server -v pq         start the TLS test listener (hybrid, pq)
  python orchestrate.py stop-server -v pq
  python orchestrate.py teardown -v pq             stop the server and delete the CA / TLS / staging
                                                   dirs on both VMs, so "run" starts fresh
  python orchestrate.py collect -v pq              record certificate / key sizes and metadata
  python orchestrate.py benchmark -v pq -n 50      run N TLS handshakes from this machine against the
                                                   running test server and record them

"run" also records per-step timings. All measurements are appended to TSV files in results/.

The variant (-v) is classical, hybrid, pq or all (default: all).

All connections start from this machine; the VMs never talk to each other.
Files move between VMs through this machine (read over SSH from one VM,
written over SSH to the other):

  PKI VM:  setup_pki_*.py                  (create Root + Intermediate CA)
  TLS VM:  setup_tls_server_*.py csr       (key + CSR)
  TLS VM -> client -> PKI VM               server.csr, server-ext.cnf
  PKI VM:  setup_pki_*.py sign             (sign the CSR)
  PKI VM -> client -> TLS VM               server.crt, server-fullchain.crt,
                                           intermediate-ca.crt, root-ca.crt
  TLS VM:  setup_tls_server_*.py install-certs
"""
import argparse
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent
INSTALL_DIR = os.environ.get("INSTALL_DIR", "/usr/local/sbin")  # scripts on the VMs
STAGE_DIR = os.environ.get("STAGE_DIR", "/tmp/pki-orch")        # transfer dir on the VMs

VARIANTS = {
    # "pki_dirs" / "tls_dirs": what the setup scripts create on each VM (their default
    # locations). Classical lists the CA subdirs, not /etc/pki itself, because /etc/pki
    # can also hold the system trust store.
    "classical": {"dir": "classical_scripts", "ca": "setup_pki.py",
                  "tls": "setup_tls_server.py", "port": None, "group": None,
                  "pki_dirs": ["/etc/pki/root-ca", "/etc/pki/intermediate-ca"],
                  "tls_dirs": ["/etc/pki/tls"]},
    "hybrid": {"dir": "hybrid_scripts", "ca": "setup_pki_hybrid.py",
               "tls": "setup_tls_server_hybrid.py", "port": 4433, "group": "X25519MLKEM768",
               "pki_dirs": ["/etc/pki-hybrid"],
               "tls_dirs": ["/etc/pki/tls-hybrid"]},
    "pq": {"dir": "pq_scripts", "ca": "setup_pki_pq.py",
           "tls": "setup_tls_server_pq.py", "port": 4443, "group": "MLKEM768",
           "pki_dirs": ["/etc/pki-pq"],
           "tls_dirs": ["/etc/pki/tls-pq"]},
}

# Measurements are appended to TSV files here; every row carries a run id and variant.
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", REPO / "results"))
RUN_ID = datetime.now().strftime("%Y%m%d-%H%M%S")
# OpenSSL 3.5+ on THIS machine, used by "benchmark" (s_client needs the PQ groups too).
CLIENT_OPENSSL = os.environ.get("CLIENT_OPENSSL", "openssl")

TSV_COLUMNS = {
    "steps": ["run_id", "timestamp", "variant", "step", "host", "seconds", "ok"],
    "artifacts": ["run_id", "timestamp", "variant", "host", "file", "bytes",
                  "signature_algorithm", "public_key_algorithm", "not_before", "not_after"],
    "handshakes": ["run_id", "timestamp", "variant", "iteration", "group", "tls_version",
                   "cipher", "signature_type", "verified", "latency_ms", "ok"],
}

CSR_FILES = ["server.csr", "server-ext.cnf"]
SIGNED_FILES = ["server.crt", "server-fullchain.crt", "intermediate-ca.crt", "root-ca.crt"]

q = shlex.quote

# openssl35: latest OpenSSL release of the 3.5 series (the LTS the PQ/hybrid scripts need),
# built from source into its own prefix so the system OpenSSL is untouched.
OPENSSL_SERIES = os.environ.get("OPENSSL_SERIES", "3.5")
OPENSSL_PREFIX = os.environ.get("OPENSSL_PREFIX", "/opt/openssl35")
OPENSSL_WRAPPER = os.environ.get("OPENSSL_WRAPPER", "/usr/local/bin/openssl35")

# Runs on each VM as root (plain POSIX sh).
OPENSSL_INSTALL_SCRIPT = r"""#!/bin/sh
set -eu
BASE=https://www.openssl.org/source

if ! command -v gcc >/dev/null || ! command -v make >/dev/null || ! command -v perl >/dev/null \
   || ! command -v curl >/dev/null; then
    echo "installing build dependencies"
    if command -v apt-get >/dev/null; then
        apt-get update && apt-get install -y build-essential perl curl ca-certificates
    elif command -v dnf >/dev/null; then
        dnf install -y gcc make perl perl-IPC-Cmd perl-core curl ca-certificates
    elif command -v yum >/dev/null; then
        yum install -y gcc make perl perl-IPC-Cmd perl-core curl ca-certificates
    else
        echo "no supported package manager; install gcc, make, perl and curl" >&2; exit 1
    fi
fi

latest=$(curl -fsSL "$BASE/" | grep -o "openssl-${OPENSSL_SERIES}\.[0-9]*\.tar\.gz" \
         | sort -uV | tail -n 1 | sed 's/\.tar\.gz$//')
[ -n "$latest" ] || { echo "could not find an OpenSSL ${OPENSSL_SERIES}.x release" >&2; exit 1; }
version=${latest#openssl-}
echo "latest OpenSSL ${OPENSSL_SERIES} release: $version"

if [ -x "$OPENSSL_WRAPPER" ] && "$OPENSSL_WRAPPER" version 2>/dev/null | grep -q "^OpenSSL $version "; then
    echo "openssl35 is already at $version"; exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSLO "$BASE/$latest.tar.gz"
curl -fsSL "$BASE/$latest.tar.gz.sha256" -o expected.sha256
expected=$(awk '{print $1}' expected.sha256)
actual=$(sha256sum "$latest.tar.gz" | awk '{print $1}')
[ "$expected" = "$actual" ] || { echo "checksum mismatch for $latest.tar.gz" >&2; exit 1; }

tar xzf "$latest.tar.gz"
cd "$latest"
./Configure --prefix="$OPENSSL_PREFIX" --openssldir="$OPENSSL_PREFIX/ssl" --libdir=lib \
    "-Wl,-rpath,$OPENSSL_PREFIX/lib"
make -j"$(nproc)"
make install_sw install_ssldirs

cat > "$OPENSSL_WRAPPER" <<EOF
#!/bin/sh
export LD_LIBRARY_PATH="$OPENSSL_PREFIX/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "$OPENSSL_PREFIX/bin/openssl" "\$@"
EOF
chmod 755 "$OPENSSL_WRAPPER"
"$OPENSSL_WRAPPER" version
"""


# --- connections ------------------------------------------------------------
def ssh(host, command):
    """Run a command on a VM. Uses a TTY when we have one, so sudo can prompt."""
    tty = "-t" if sys.stdin.isatty() else "-T"
    subprocess.run(["ssh", tty, host, command], check=True)


def ssh_sudo(host, command):
    ssh(host, f"sudo {command}")


# --- results ----------------------------------------------------------------
def record(table, **fields):
    """Append one row to results/<table>.tsv (writes the header for a new file)."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{table}.tsv"
    row = {"run_id": RUN_ID, "timestamp": datetime.now().isoformat(timespec="seconds"), **fields}
    new = not path.exists() or path.stat().st_size == 0
    with open(path, "a", encoding="utf-8", newline="") as f:
        if new:
            f.write("\t".join(TSV_COLUMNS[table]) + "\n")
        f.write("\t".join(str(row.get(c, "")).replace("\t", " ").replace("\n", " ")
                          for c in TSV_COLUMNS[table]) + "\n")


def timed(variant, step, host, func, *args):
    """Run func(*args) and record how long it took (includes SSH and sudo overhead)."""
    start = time.perf_counter()
    ok = False
    try:
        func(*args)
        ok = True
    finally:
        record("steps", variant=variant, step=step, host=host.split("@")[-1],
               seconds=f"{time.perf_counter() - start:.3f}", ok=int(ok))


# --- file transfers ---------------------------------------------------------
def read_file(host, path):
    """Return the contents of a file on a VM."""
    result = subprocess.run(["ssh", "-T", host, f"cat {q(path)}"],
                            check=True, stdout=subprocess.PIPE)
    return result.stdout


def write_file(host, path, data):
    """Write bytes to a file on a VM."""
    subprocess.run(["ssh", "-T", host, f"cat > {q(path)}"], check=True, input=data)


def copy_between(src_host, src_path, dst_host, dst_path):
    """Copy a file from one VM to another through this machine."""
    print(f"  {src_host}:{src_path} -> {dst_host}:{dst_path}")
    write_file(dst_host, dst_path, read_file(src_host, src_path))


def upload(host, local_path, remote_path):
    """Copy a local file to a VM."""
    print(f"  {local_path.name} -> {host}:{remote_path}")
    write_file(host, remote_path, local_path.read_bytes())


# --- paths ------------------------------------------------------------------
def stage_dir(variant):
    return f"{STAGE_DIR}/{variant}"


def installed(script):
    return f"{INSTALL_DIR}/{script}"


# --- checks -----------------------------------------------------------------
def check_connection(host):
    print(f"== checking SSH to {host}")
    ssh(host, "echo connected to $(hostname)")


def check_python(host):
    print(f"== checking python3 on {host}")
    ssh(host, "python3 --version")


def check_sudo(host):
    print(f"== checking sudo on {host}")
    ssh_sudo(host, "true")


# --- steps ------------------------------------------------------------------
def make_stage_dir(host, variant):
    ssh(host, f"mkdir -p {q(stage_dir(variant))}")


def deploy_script(host, variant, script):
    print(f"== deploying {script} to {host}")
    local = REPO / VARIANTS[variant]["dir"] / script
    staged = f"{stage_dir(variant)}/{script}"
    make_stage_dir(host, variant)
    upload(host, local, staged)
    ssh_sudo(host, f"install -m 755 {q(staged)} {q(installed(script))}")


def ca_init(pki, variant):
    print(f"== [{variant}] initializing CA on {pki}")
    ssh_sudo(pki, q(installed(VARIANTS[variant]["ca"])))


def tls_make_csr(tls, variant):
    print(f"== [{variant}] creating key and CSR on {tls}")
    make_stage_dir(tls, variant)
    ssh_sudo(tls, f"{q(installed(VARIANTS[variant]['tls']))} csr {q(stage_dir(variant))}")


def transfer_csr(tls, pki, variant):
    print(f"== [{variant}] copying CSR from TLS VM to PKI VM")
    make_stage_dir(pki, variant)
    for name in CSR_FILES:
        path = f"{stage_dir(variant)}/{name}"
        copy_between(tls, path, pki, path)


def ca_sign(pki, variant):
    print(f"== [{variant}] signing CSR on {pki}")
    stage = stage_dir(variant)
    ssh_sudo(pki, f"{q(installed(VARIANTS[variant]['ca']))} sign "
                  f"{q(stage + '/server.csr')} {q(stage + '/server-ext.cnf')} {q(stage)}")


def transfer_certs(pki, tls, variant):
    print(f"== [{variant}] copying signed certificates from PKI VM to TLS VM")
    for name in SIGNED_FILES:
        path = f"{stage_dir(variant)}/{name}"
        copy_between(pki, path, tls, path)


def tls_install_certs(tls, variant):
    print(f"== [{variant}] installing certificates on {tls}")
    ssh_sudo(tls, f"{q(installed(VARIANTS[variant]['tls']))} install-certs "
                  f"{q(stage_dir(variant))}")


def start_test_server(tls, variant):
    print(f"== [{variant}] starting test server on {tls}")
    log = f"{stage_dir(variant)}/test-server.log"
    make_stage_dir(tls, variant)
    # "sudo -v" asks for the password up front, before the server goes to the background.
    ssh(tls, f"sudo -v && sudo setsid nohup {q(installed(VARIANTS[variant]['tls']))} "
             f"test-server > {q(log)} 2>&1 < /dev/null &")


def check_test_server(tls, variant):
    port = VARIANTS[variant]["port"]
    print(f"== [{variant}] checking test server on {tls}:{port}")
    # "[t]" stops pgrep from matching this command line itself.
    ssh(tls, f"sleep 2; pgrep -f 's_server -accep[t] {port}' >/dev/null "
             f"&& echo 'listening on port {port}' "
             f"|| {{ echo 'test server is not running:'; cat {q(stage_dir(variant))}/test-server.log; exit 1; }}")


def stop_test_server(tls, variant):
    port = VARIANTS[variant]["port"]
    print(f"== [{variant}] stopping test server on {tls}:{port}")
    ssh_sudo(tls, f"pkill -f 's_server -accep[t] {port}'")


def remove_dirs(host, paths):
    for path in paths:
        # Never rm -rf "/" or a top-level dir like /etc.
        if not path.startswith("/") or len(path.strip("/").split("/")) < 2:
            raise ValueError(f"refusing to remove {path!r}")
        print(f"  removing {host}:{path}")
        ssh_sudo(host, f"rm -rf -- {q(path)}")


def teardown_variant(pki, tls, variant):
    info = VARIANTS[variant]
    print(f"== [{variant}] tearing down {pki} and {tls}")
    if info["port"]:
        try:
            stop_test_server(tls, variant)
        except subprocess.CalledProcessError:
            pass  # pkill exits 1 when nothing was running
    remove_dirs(pki, info["pki_dirs"] + [stage_dir(variant)])
    remove_dirs(tls, info["tls_dirs"] + [stage_dir(variant)])


# --- data collection --------------------------------------------------------
# Runs on a VM as root: one TSV line per file (name, bytes, signature alg, public key alg, dates).
COLLECT_SCRIPT = r"""
O=@WRAPPER@; [ -x "$O" ] || O=openssl
out=@OUT@
: > "$out"
emit() {
    f=$1; sig=; pub=; nb=; na=
    case $f in
        */server-fullchain.crt) ;;
        *.crt)
            t=$("$O" x509 -noout -text -in "$f")
            sig=$(echo "$t" | grep -m1 'Signature Algorithm' | sed 's/.*: *//')
            pub=$(echo "$t" | grep -m1 'Public Key Algorithm' | sed 's/.*: *//')
            nb=$("$O" x509 -noout -startdate -in "$f" | cut -d= -f2)
            na=$("$O" x509 -noout -enddate -in "$f" | cut -d= -f2) ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(basename "$f")" "$(wc -c < "$f")" "$sig" "$pub" "$nb" "$na" >> "$out"
}
for f in @STAGE@/server.csr @STAGE@/server.crt @STAGE@/server-fullchain.crt \
         @STAGE@/intermediate-ca.crt @STAGE@/root-ca.crt; do
    [ -f "$f" ] && emit "$f"
done
for f in $(find @DIRS@ -name '*.key' 2>/dev/null); do emit "$f"; done
chmod 644 "$out"
exit 0
"""


def collect_artifacts(host, variant, dirs):
    print(f"== [{variant}] collecting artifact sizes and metadata from {host}")
    stage = stage_dir(variant)
    out = f"{stage}/artifacts.tsv"
    make_stage_dir(host, variant)
    script = (COLLECT_SCRIPT.replace("@WRAPPER@", q(OPENSSL_WRAPPER)).replace("@OUT@", q(out))
              .replace("@STAGE@", q(stage)).replace("@DIRS@", " ".join(q(d) for d in dirs)))
    ssh_sudo(host, f"sh -c {q(script)}")
    for line in read_file(host, out).decode().splitlines():
        name, size, sig, pub, nb, na = (line.split("\t") + [""] * 6)[:6]
        record("artifacts", variant=variant, host=host.split("@")[-1], file=name, bytes=size,
               signature_algorithm=sig, public_key_algorithm=pub, not_before=nb, not_after=na)


def require_pq_client():
    try:
        version = subprocess.run([CLIENT_OPENSSL, "version"], capture_output=True, text=True,
                                 check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit(f"Cannot run CLIENT_OPENSSL={CLIENT_OPENSSL!r}")
    if not re.match(r"OpenSSL\s3\.([5-9]|\d\d)\.", version):
        raise SystemExit(f"benchmark needs OpenSSL 3.5+ on this machine (PQ groups); "
                         f"{CLIENT_OPENSSL!r} reports: {version}\n"
                         "Set CLIENT_OPENSSL to a 3.5+ openssl binary.")
    print(f"== client: {version}")


def handshake_once(host, port, group, ca_file):
    """One TLS 1.3 handshake with s_client; returns (latency_ms, ok, info)."""
    cmd = [CLIENT_OPENSSL, "s_client", "-connect", f"{host}:{port}", "-tls1_3",
           "-groups", group, "-CAfile", str(ca_file), "-verify_ip", host, "-brief"]
    start = time.perf_counter()
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                            timeout=30)
    ms = (time.perf_counter() - start) * 1000
    text = result.stdout + result.stderr  # -brief prints to stderr
    info = {}
    for key, label in (("tls_version", "Protocol version"), ("cipher", "Ciphersuite"),
                       ("signature_type", "Signature type"), ("verified", "Verification")):
        m = re.search(rf"^{label}:\s*(.+)$", text, re.M)
        info[key] = m.group(1).strip() if m else ""
    ok = "CONNECTION ESTABLISHED" in text and info["verified"] == "OK"
    return ms, ok, info


def benchmark_variant(tls, variant, count):
    info = VARIANTS[variant]
    host = tls.split("@")[-1]
    ca_file = RESULTS_DIR / "ca" / f"{variant}-root-ca.crt"
    ca_file.parent.mkdir(parents=True, exist_ok=True)
    ca_file.write_bytes(read_file(tls, f"{stage_dir(variant)}/root-ca.crt"))
    print(f"== [{variant}] {count} handshakes to {host}:{info['port']} ({info['group']})")
    handshake_once(host, info["port"], info["group"], ca_file)  # warm-up, not recorded
    for i in range(1, count + 1):
        ms, ok, res = handshake_once(host, info["port"], info["group"], ca_file)
        record("handshakes", variant=variant, iteration=i, group=info["group"],
               latency_ms=f"{ms:.1f}", ok=int(ok), **res)
        if not ok:
            print(f"  handshake {i} failed (is the test server running? try start-server)")


# --- commands ---------------------------------------------------------------
def cmd_check(pki, tls, variants, count=None):
    for host in (pki, tls):
        check_connection(host)
        check_python(host)
        check_sudo(host)


def cmd_install_openssl(pki, tls, variants, count=None):
    for host in (pki, tls):
        print(f"== installing openssl35 on {host}")
        staged = f"{STAGE_DIR}/install-openssl35.sh"
        ssh(host, f"mkdir -p {q(STAGE_DIR)}")
        write_file(host, staged, OPENSSL_INSTALL_SCRIPT.encode())
        ssh_sudo(host, f"env OPENSSL_SERIES={q(OPENSSL_SERIES)} "
                       f"OPENSSL_PREFIX={q(OPENSSL_PREFIX)} OPENSSL_WRAPPER={q(OPENSSL_WRAPPER)} "
                       f"sh {q(staged)}")


def cmd_deploy(pki, tls, variants, count=None):
    for v in variants:
        deploy_script(pki, v, VARIANTS[v]["ca"])
        deploy_script(tls, v, VARIANTS[v]["tls"])


def cmd_run(pki, tls, variants, count=None):
    cmd_deploy(pki, tls, variants)
    for v in variants:
        timed(v, "ca_init", pki, ca_init, pki, v)
        timed(v, "tls_csr", tls, tls_make_csr, tls, v)
        timed(v, "transfer_csr", tls, transfer_csr, tls, pki, v)
        timed(v, "ca_sign", pki, ca_sign, pki, v)
        timed(v, "transfer_certs", pki, transfer_certs, pki, tls, v)
        timed(v, "tls_install_certs", tls, tls_install_certs, tls, v)
        cmd_collect(pki, tls, [v])
        print(f"== [{v}] done")


def cmd_collect(pki, tls, variants, count=None):
    for v in variants:
        collect_artifacts(pki, v, VARIANTS[v]["pki_dirs"])
        collect_artifacts(tls, v, VARIANTS[v]["tls_dirs"])


def cmd_benchmark(pki, tls, variants, count=50):
    require_pq_client()
    for v in variants:
        benchmark_variant(tls, v, count)


def cmd_start_server(pki, tls, variants, count=None):
    for v in variants:
        start_test_server(tls, v)
        check_test_server(tls, v)


def cmd_stop_server(pki, tls, variants, count=None):
    for v in variants:
        stop_test_server(tls, v)


def cmd_teardown(pki, tls, variants, count=None):
    for v in variants:
        teardown_variant(pki, tls, v)
        print(f"== [{v}] torn down")


COMMANDS = {
    "install-openssl": cmd_install_openssl,
    "teardown": cmd_teardown,
    "collect": cmd_collect,
    "benchmark": cmd_benchmark,
    "check": cmd_check,
    "deploy": cmd_deploy,
    "run": cmd_run,
    "start-server": cmd_start_server,
    "stop-server": cmd_stop_server,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("-v", "--variant", choices=[*VARIANTS, "all"], default="all")
    parser.add_argument("-n", "--count", type=int, default=50,
                        help="handshakes per variant for benchmark (default: 50)")
    parser.add_argument("--user", default="owen", help="SSH user on both VMs")
    parser.add_argument("--pki-host", default="192.168.193.147")
    parser.add_argument("--tls-host", default="192.168.205.100")
    args = parser.parse_args()

    variants = list(VARIANTS) if args.variant == "all" else [args.variant]
    if args.command in ("start-server", "stop-server", "benchmark"):
        variants = [v for v in variants if VARIANTS[v]["port"]]
        if not variants:
            parser.error("the classical variant has no test server")

    pki = f"{args.user}@{args.pki_host}"
    tls = f"{args.user}@{args.tls_host}"
    try:
        COMMANDS[args.command](pki, tls, variants, args.count)
    except subprocess.CalledProcessError as e:
        print(f"\nFAILED (exit {e.returncode}): {' '.join(e.cmd)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
