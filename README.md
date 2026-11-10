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
