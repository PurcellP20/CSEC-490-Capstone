# CSEC-490 Capstone

`orchestrate.py` runs the 2-VM PKI setups (classical, hybrid, and post-quantum) from one client machine over SSH.

## Usage

```
python orchestrate.py <command> [-v VARIANT]
```

| Command | Description |
|---|---|
| `check` | Check SSH, python3 and sudo on both VMs |
| `install-openssl` | Build the latest OpenSSL 3.5.x from source on both VMs and install it as `/usr/local/bin/openssl35` (needed by the hybrid and pq scripts). Run before `run`. |
| `deploy -v pq` | Copy the scripts to both VMs |
| `run -v pq` | Deploy, then run the full CA / TLS setup |
| `start-server -v pq` | Start the TLS test listener (hybrid, pq only) |
| `stop-server -v pq` | Stop the TLS test listener |
| `collect -v pq` | Record key / CSR / certificate sizes and certificate metadata (also done at the end of `run`) |
| `benchmark -v pq -n 50` | Run N TLS 1.3 handshakes from this machine against the running test server (hybrid, pq only) |
| `teardown -v pq` | Stop the server and delete the CA / TLS / staging directories on both VMs, so `run` starts fresh |

## Options

| Option | Description |
|---|---|
| `-v`, `--variant` | `classical`, `hybrid`, `pq` or `all` (default: `all`) |
| `--user` | SSH user on both VMs (default: `owen`) |
| `--pki-host` | PKI VM address |
| `--tls-host` | TLS VM address |

## Environment variables

| Variable | Description |
|---|---|
| `OPENSSL_SERIES` | OpenSSL series `install-openssl` builds (default: `3.5`) |
| `OPENSSL_PREFIX` | Install prefix on the VMs (default: `/opt/openssl35`) |
| `OPENSSL_WRAPPER` | Path of the `openssl35` wrapper (default: `/usr/local/bin/openssl35`) |
| `INSTALL_DIR` | Where scripts are installed on the VMs (default: `/usr/local/sbin`) |
| `STAGE_DIR` | Transfer directory on the VMs (default: `/tmp/pki-orch`) |

`install-openssl` needs outbound internet access from the VMs (openssl.org). It verifies the tarball's SHA-256, leaves the system OpenSSL untouched, and does nothing if `openssl35` is already at the latest release.

## Collected data

Measurements are appended to tab-separated files in `results/` (override with `RESULTS_DIR`). Every row has a `run_id` and `variant`, so repeated runs accumulate and open directly in Excel or pandas.

| File | Written by | Columns |
|---|---|---|
| `steps.tsv` | `run` | step name, host, seconds, ok. Timed from the client, so it includes SSH and sudo overhead. |
| `artifacts.tsv` | `run`, `collect` | file, bytes, signature algorithm, public-key algorithm, validity dates |
| `handshakes.tsv` | `benchmark` | iteration, group, TLS version, cipher, signature type, verified, latency_ms, ok |

`benchmark` runs `openssl s_client` on this machine, so it needs OpenSSL 3.5+ locally (set `CLIENT_OPENSSL` to its path). Start the listener first with `start-server`.
