# CSEC-490 Capstone

`orchestrate.py` runs the 2-VM PKI setups (classical, hybrid, and post-quantum) from one client machine over SSH.

## Usage

```
python orchestrate.py <command> [-v VARIANT]
```

| Command | Description |
|---|---|
| `check` | Check SSH, python3 and sudo on both VMs |
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
