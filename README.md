![TwinLink — GRE tunneling for Linux, with kernel forwarding and rathole TCP](docs/assets/readme-banner.png)

# TwinLink

TwinLink connects two Linux VPSs through an IPv4 GRE tunnel and forwards public traffic from **VPS1** to services reachable from **VPS2**. Manage tunnels and forwarding with an interactive menu or a scriptable CLI.

```text
Client → VPS1 (public port) → GRE tunnel → VPS2 → Backend service
```

## How It Works

TwinLink sets up a private GRE tunnel between two Linux servers and then uses that tunnel to forward traffic:

```mermaid
flowchart LR
  Client[Client] -->|public IP:port| VPS1
  VPS1 -->|GRE tunnel| VPS2
  VPS2 -->|private network| Backend[Backend Service]
```

1. **Tunnel creation** — A GRE tunnel creates a private point-to-point link between VPS1 and VPS2 using their public IPs. Each side gets a private IP (e.g. `10.77.0.1` ↔ `10.77.0.2`).

2. **Port forwarding** — Traffic arriving on VPS1's public port is forwarded through the GRE tunnel to VPS2, which delivers it to the backend service. Two methods are available:
   - **Kernel forwarding** — Uses nftables DNAT rules for TCP/UDP. Fast and lightweight, supports port ranges up to 256 ports.
   - **Rathole forwarding** — Uses the [rathole](https://github.com/rapiz1/rathole) reverse proxy for TCP. Adds **Noise encryption** inside the tunnel and can reach services on VPS2's localhost.

3. **Pairing** — Configuration is transferred between servers using base64 pairing codes (copy/paste). No SSH or direct connection between the CLI instances is needed.

4. **Persistence** — All tunnels and forwards are managed through systemd services that survive reboots.

## Features

- Create, pair, monitor, and manage multiple GRE tunnels
- Kernel (TCP/UDP) and Rathole (encrypted TCP) forwarding modes
- Base64 pairing codes for easy peer setup — no SSH needed
- Systemd integration for persistence across reboots
- Preview changes before applying, with rollback on failure
- Diagnostics: health checks, drift detection, `doctor` command
- Interactive menu and scriptable CLI with JSON output
- Zero Python dependencies — standard library only

## Requirements

On **both VPSs**:

- Linux with systemd and Python **3.9+** (Debian/Ubuntu or Fedora/RHEL)
- Root access
- Firewall allowing **IP protocol 47 (GRE)** between the servers

The installer handles required packages: iproute2, nftables, conntrack, and ICMP tools.

## Installation

Run on **both VPSs**:

```sh
git clone https://github.com/mojtabaesl/twinLink.git
cd twinLink
sudo scripts/install.sh
sudo twinlink doctor        # verify dependencies
```

Then use the interactive menu or follow the Quick Start:

```sh
sudo twinlink menu
```

## Quick Start

This example forwards ports `8080→80` and `8443→443` on VPS1 to a backend on VPS2 using Rathole with Noise encryption.

> [!NOTE]
> Commands **preview** by default. Add `--apply` to commit changes.

### 1. Create the tunnel

**VPS1:**

```sh
sudo twinlink tunnel create edge --side vps1 \
  --local-public 198.51.100.10 --remote-public 203.0.113.20 \
  --local-private 10.77.0.1/30 --remote-private 10.77.0.2/30 \
  --key 424242 --mtu 1472 --ttl 64 --apply
```

Export the pairing code and run it on VPS2:

```sh
# VPS1
sudo twinlink tunnel pair-export edge

# VPS2 — paste the code
sudo twinlink tunnel pair-import --code 'v1.COMPLETE_CODE' --apply
```

Verify connectivity on **both**:

```sh
sudo twinlink tunnel check edge --record --apply
```

### 2. Install Rathole & add forwarding (VPS1)

```sh
# Install rathole (one-time)
sudo twinlink forward install-rathole --apply

# Add forwarding — multiple ports in one config, Noise encryption is automatic
sudo twinlink forward add app --mode rathole --tunnel edge \
  --transport-port 2333 --destination-address 127.0.0.1 \
  --ports 8080:80,8443:443 --apply
```

### 3. Pair forwarding (VPS2)

Copy the pairing code printed after step 2, then paste it on VPS2:

```sh
sudo twinlink forward setup
# paste the r1.… code when prompted, review, and apply
```

Enable on **both** and test:

```sh
sudo twinlink forward enable app --apply
sudo twinlink forward check app
```

## Common Commands

| Command                              | Purpose                                   |
| ------------------------------------ | ----------------------------------------- |
| `sudo twinlink menu`                 | Interactive management menu               |
| `sudo twinlink status`               | Show all tunnels and forwards with health |
| `sudo twinlink doctor`               | Check host dependencies                   |
| `sudo twinlink forward setup`        | Guided Kernel or Rathole forwarding setup |
| `sudo twinlink tunnel list`          | List tunnels                              |
| `sudo twinlink forward list`         | List forwarding entries                   |
| `sudo twinlink tunnel check edge`    | Check tunnel connectivity                 |
| `sudo twinlink forward check web`    | Check forwarding health                   |
| `sudo twinlink forward diagnose web` | Troubleshooting diagnostics               |
| `sudo twinlink recover --apply`      | Roll back an interrupted transaction      |

## Uninstall

```sh
sudo scripts/uninstall.sh                        # remove CLI only
sudo scripts/uninstall.sh --purge-managed --cascade  # also remove tunnels & forwards
```

## Documentation

- [Command reference](docs/commands.md) — all commands, options, and exit codes
- [Operations guide](docs/operations.md) — setup, pairing, maintenance, and recovery
- [Architecture](docs/architecture.md) — packet paths, ownership, and transaction design

## Development

```sh
python3 -m unittest discover -s tests -v          # run tests (no root needed)
scripts/install.sh --build-only /tmp/twinlink.pyz  # build standalone archive
```

### Readable terminal output

Commands show concise summaries by default. Use `--verbose` for detailed
redacted payloads or `--json` for scripts (`--json` takes precedence). Both
flags work globally and after public leaf commands, for example
`twinlink --verbose status` or `twinlink tunnel show edge --json`.
Color is enabled only on terminals and disabled by nonempty `NO_COLOR` or
`TERM=dumb`. Pairing codes remain complete and uncolored; default
`pair-export` prints only the code. See [command output](docs/commands.md#terminal-output).
