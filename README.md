![twinLink — GRE tunneling for Linux, with kernel forwarding and rathole TCP](docs/assets/readme-banner.png)

# twinLink

twinLink connects two Linux VPSs through an IPv4 GRE tunnel and forwards public traffic from **VPS1** to services reachable from **VPS2**. Manage tunnels and forwarding with an interactive menu or a scriptable CLI.

```text
Client → VPS1 (public port) → GRE tunnel → VPS2 → Backend service
```

[Installation](#installation) · [Quick start](#quick-start) · [Commands](docs/commands.md) · [Operations guide](docs/operations.md)

## Features

- **GRE tunnels:** create, pair, monitor, and manage multiple tunnels.
- **Two forwarding modes:** kernel TCP/UDP forwarding with port ranges of up to 256 ports, or rathole TCP forwarding with support for local services on VPS2.
- **Two main tasks:** create GRE tunnels, then set up port forwarding. Kernel and Rathole share one Forwarding menu and CLI command group.
- **Easy peer setup:** copy/paste GRE, Kernel and Rathole base64 pairing codes, including several Rathole forwarding ports in one code.
- **Guided forwarding setup:** reuse saved GRE details, choose Kernel or Rathole, and enter forwarding ports. Rathole installation, tokens and Noise keys are handled automatically.
- **Persistent services:** systemd integration restores enabled resources after reboot.
- **Preview before applying:** inspect changes before committing, with rollback and interrupted-transaction recovery.
- **Diagnostics and automation:** peer reachability checks, drift detection, JSON output, and an interactive menu.
- **No Python dependencies:** uses the Python standard library.

GRE does **not** encrypt or authenticate traffic. New Rathole forwards use **Noise encryption** inside GRE and support **rathole 0.5.0, TCP only**. Existing TCP configurations retain their transport until explicitly upgraded. There is no web panel or SOCKS proxy.

## Requirements

On **both VPSs**:

- Linux with systemd and Python **3.9+**. The installer supports Debian/Ubuntu (`apt-get`) and Fedora/Rocky/Alma/RHEL (`dnf`).
- Root access for network changes.
- Provider and host firewalls that allow **IP protocol 47 (GRE)** between the servers, plus peer ICMP over the private tunnel network. GRE is not TCP/UDP port 47.
- Firewall rules that allow the intended public service and forwarded traffic.

The installer installs the required networking tools: iproute2/iproute, nftables, conntrack, and ICMP diagnostics.

## Installation

Run on **both VPSs** from a local checkout:

```sh
git clone https://github.com/mojtabaesl/twinLink.git
cd twinLink
sudo scripts/install.sh
sudo twinlink doctor
```

Then open the guided menu, or follow the CLI quick start below:

```sh
sudo twinlink menu
```

The main menu has **GRE tunnels** and **Port forwarding (Kernel or Rathole)**, plus system tools for health, dependencies and recovery. All forwarding setup, pairing, lifecycle operations and Rathole config paths are inside Port forwarding.

The command is installed at `/usr/local/bin/twinlink`; managed services use `/usr/local/libexec/twinlink-runtime`. Use `--skip-deps` with the installer to check existing dependencies without changing packages.

Rathole can be installed by twinLink on Linux x86_64 or ARM64:

```sh
sudo twinlink forward install-rathole --apply
```

This downloads the pinned official **0.5.0** release over HTTPS, checks its version and Noise support, and installs `/usr/local/bin/rathole`. Compatible existing executables are reused; other existing files are never replaced. Optionally supply `--sha256 TRUSTED_ARCHIVE_SHA256` to verify the downloaded ZIP against a trusted checksum. When GitHub is unreachable, copy a trusted matching binary from another host and select it with `--rathole-binary`.

You can also check a separately obtained executable during program installation:

```sh
sudo scripts/install.sh --rathole /opt/rathole/rathole --rathole-sha256 TRUSTED_SHA256
```

Replace `TRUSTED_SHA256` with a trusted checksum of the executable. When using a custom path, pass `--rathole-binary /opt/rathole/rathole` before the CLI command.

## Forward ports with minimum setup

After pairing and verifying GRE on both servers, run on each server, or choose **Port forwarding → Set up forwarding / add ports** in the menu:

```sh
sudo twinlink forward setup
```

The wizard reads saved GRE configuration to detect this server's role and reuse both public/private endpoints. A single running, verified tunnel is selected automatically; with several VPS1 tunnels, choose one from a numbered list. No tunnel name or endpoint needs retyping.

On **VPS1**, choose the forwarding method:

- **Kernel:** choose TCP or UDP, a saved backend or VPS2 address, and public/backend ports or ranges. Relay ports are allocated automatically. Copy the resulting **`f1.` pairing text**.
- **Rathole:** enter a **Rathole name** (e.g. `edge-rathole`) and **connection port** (default `2333`), choose a backend (including VPS2 loopback), and enter mappings such as `8080:80,8443:443,9000`. Installation and Noise credentials are automatic. Copy the resulting **`r1.` pairing text**.

Rathole services share **one TOML config, one process/systemd unit, one connection port and one Noise keypair**, using a shared `default_token`. Service names are generated from the Rathole name and public port. Adding services to an existing config reuses its name, port and credentials.

For older installations with separate configs per port, choose **Combine saved forwarding into one Rathole config** in the wizard. It asks for the shared name/port, removes the old configs/units transactionally, and prints fresh pairing text to import on VPS2. Existing forwarding tokens are preserved with service-specific overrides when needed. Re-exporting an existing setup requires no port/name/address entry. Updating a shared config briefly restarts all its services together.

On **VPS2**, paste either code when prompted. The code identifies the forwarding method and matching saved GRE tunnel automatically. Review and apply once to configure/start imported forwarding and enable it at boot. Rathole codes contain service tokens and Noise public keys; server private keys stay on VPS1. Transfer those codes privately. A role question appears only when this host has saved eligible tunnels in both VPS roles.

To skip the method question, use `forward setup --mode kernel` or `forward setup --mode rathole`. Existing `twinlink rathole …` commands remain compatible.

To display config paths and editor commands without opening an editor:

```sh
sudo twinlink forward config edge-rathole
# Shared config: /var/lib/twinlink/rathole/edge-rathole.toml
# Edit manually: sudo vim /var/lib/twinlink/rathole/edge-rathole.toml
```

Manual TOML edits are overwritten on reapply or boot restore. Use `forward edit` for persistent port/address changes, then generate a fresh Rathole pairing code. See [Rathole commands](docs/commands.md#rathole-installation-noise-and-base64-pairing).

## Quick start

This example exposes VPS1 port `8080` and forwards it to `10.20.30.40:80`, reachable from VPS2. Replace all example public and backend addresses with your own.

**Change commands preview by default.** Add `--apply` to commit after confirmation. For scripts, use `--apply --yes` after reviewing the preview.

### 1. Create and pair the tunnel

On **VPS1**, preview the tunnel, then repeat with `--apply`:

```sh
sudo twinlink tunnel create edge --side vps1 \
  --local-public 198.51.100.10 --remote-public 203.0.113.20 \
  --local-private 10.77.0.1/30 --remote-private 10.77.0.2/30 \
  --key 424242 --mtu 1472 --ttl 64
```

After applying, export its pairing code:

```sh
sudo twinlink tunnel pair-export edge
```

On **VPS2**, paste the complete `v1.` code. Import swaps the endpoints automatically:

```sh
sudo twinlink tunnel pair-import --code 'v1.COMPLETE_CODE'
sudo twinlink tunnel pair-import --code 'v1.COMPLETE_CODE' --apply
```

On **both VPSs**, verify peer connectivity and record the successful check:

```sh
sudo twinlink tunnel check edge
sudo twinlink tunnel check edge --record --apply
```

Creation/import normally starts and enables the tunnel. Forwarding requires recorded GRE verification; an interface marked UP is insufficient. If the check fails, run `sudo twinlink tunnel diagnose edge` before continuing.

### 2. Add forwarding on VPS1

Start the backend service on VPS2 or a host reachable from it, then run on **VPS1**:

```sh
sudo twinlink forward add web --tunnel edge --mode kernel --protocol tcp \
  --bind-address 198.51.100.10 --bind-port 8080 \
  --destination-address 10.20.30.40 --destination-port 80 --apply
```

Use `--protocol udp` for kernel UDP forwarding. Use `--mode rathole --protocol tcp` for rathole TCP; it also allows a VPS2 loopback backend such as `127.0.0.1`. See the [operations guide](docs/operations.md#add-and-pair-forwarding) for mode details and examples.

### 3. Transfer forwarding to VPS2

The successful add prints a pairing code. To export it again on **VPS1**:

```sh
sudo twinlink forward pair-export web
```

On **VPS2**, paste the code into the common forwarding wizard and review/apply:

```sh
sudo twinlink forward setup
```

The wizard starts/enables imported forwarding. On **both VPSs**:

```sh
sudo twinlink forward enable web --apply
sudo twinlink forward check web
```

`enable` starts the entry and enables it at boot. Test the service from a third host at `VPS1_PUBLIC_IP:8080`. Private file transfer remains available through `forward export` / `forward import`.

## Common commands

Examples use tunnel `edge` and forwarding entry `web`.

| Command | Purpose |
| --- | --- |
| `sudo twinlink menu` | Open the interactive management menu. |
| `sudo twinlink forward setup` | Set up Kernel or Rathole forwarding, or import the peer's pairing text. |
| `sudo twinlink forward menu` | Open forwarding management directly. |
| `sudo twinlink doctor` | Check host dependencies and systemd availability. |
| `sudo twinlink status` | Show all managed tunnels and forwards with observed health. |
| `sudo twinlink tunnel list` | List tunnels and their status. |
| `sudo twinlink forward list` | List forwarding entries and their status. |
| `sudo twinlink tunnel check edge` | Check GRE configuration and peer reachability. |
| `sudo twinlink forward check web` | Check forwarding health. |
| `sudo twinlink forward diagnose web` | Gather troubleshooting evidence. |
| `sudo twinlink forward disable web --apply` | Stop forwarding and disable it at boot. |
| `sudo twinlink forward enable web --apply` | Start forwarding and enable it at boot. |
| `sudo twinlink forward reapply web --apply` | Repair configuration drift. |
| `sudo twinlink recover --apply` | Roll back an interrupted transaction. |

See the **[full command reference](docs/commands.md)** for every command, lifecycle behavior, options, and examples. Use `twinlink --help` or `twinlink <group> <command> --help` for CLI usage.

Shared configuration changes must be exported and imported again on the peer. Forward edits stop/disable the edited entry; enable it on both hosts after synchronizing. See [daily operation](docs/operations.md#daily-operation) and [recovery](docs/operations.md#drift-and-recovery).

## Uninstall

Remove the command launcher while retaining managed networking and the runtime needed by its services:

```sh
sudo scripts/uninstall.sh
```

To remove managed tunnels and forwards as well:

```sh
sudo scripts/uninstall.sh --purge-managed --cascade
```

State/backups, installed OS packages, and separately installed rathole binaries remain. See [removal details](docs/operations.md#uninstall).

## Development and documentation

```sh
# Run unit tests without root
python3 -m unittest discover -s tests -v

# Build a standalone archive without installing (also works on macOS)
scripts/install.sh --build-only /tmp/twinlink.pyz
python3 /tmp/twinlink.pyz --help
```

- [Command reference](docs/commands.md): commands, options, and exit codes.
- [Operations guide](docs/operations.md): advanced setup, pairing, maintenance, recovery, and Linux integration tests.
- [Architecture](docs/architecture.md): packet paths, resource ownership, and transaction design.
- [Verification record](docs/verification.md): completed checks and outstanding Linux/two-server validation.

Linux packet delivery, systemd behavior, and real reboot recovery still require validation in the target environment; unit tests alone do not establish end-to-end connectivity.
