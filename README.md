# TwinLink

Configure two Linux VPSs once, then choose how traffic reaches your backend.
VPS1 receives public connections; VPS2 connects them to your service.

```text
Client → VPS1 public port → selected profile → VPS2 → backend
```

**Version 2.0.0a1 is a development release.** Linux/systemd and real two-VPS
acceptance are still unverified. Paqet activation is not available yet.
See [tested behavior and remaining work](docs/verification.md).

## Choose a profile

One profile runs per pair. Switching is manual; there is no automatic failover.
Service mappings and the shared transport port are configured once per pair.
Kernel forwarding uses GRE rather than a TCP/UDP transport connection.

| Profile | Traffic | Connection between VPSs | Backend on VPS2 localhost |
| --- | --- | --- | --- |
| `direct-rathole` | TCP | Rathole with Noise encryption over public TCP | Yes |
| `gre-rathole` | TCP | Rathole with Noise encryption over GRE | Yes |
| `gre-kernel` | TCP / UDP | GRE with kernel forwarding; no encryption | No |
| `direct-paqet` | Not available | Configuration generation only; activation is gated | Not qualified |

The walkthrough below uses **direct-rathole**. It does not require GRE.

## Before you start

On both VPSs you need Linux with systemd, Python 3.9+, Git, and root access.
The installer supports Debian/Ubuntu and Fedora/Rocky/Alma/RHEL and installs
network tools. Rathole profiles also need a trusted **Rathole 0.5.0** executable
with Noise support on both hosts.

Allow the chosen path in your provider and host firewalls:

- This walkthrough: clients → VPS1 TCP `8081`, and VPS2 → VPS1 TCP `3456`.
- GRE profiles additionally need IP protocol **47** between the VPSs. This is
  an IP protocol number, not a TCP/UDP port.
- The backend must be reachable from VPS2. Kernel forwarding cannot use a
  loopback backend.

Replace the example addresses with the public IPv4 addresses assigned to your
servers. Commands below use `--apply --yes` to execute changes; omit both flags
to preview a mutation first. Exports write files immediately.

## 1. Install on both VPSs

Install TwinLink, then prepare Rathole **before creating or importing a pair**:

```sh
git clone https://github.com/mojtabaesl/twinLink.git
cd twinLink
sudo scripts/install.sh
sudo twinlink rathole install --apply --yes
twinlink --version
```

If an earlier installation failed or was interrupted, update the checkout and
resume from it. This works even when `twinlink` is not installed yet:

```sh
git pull --ff-only
sudo scripts/install.sh --resume
```

Resume saves a private baseline backup and retains the original package
snapshots. Backups are stored beside the state directory (by default,
`/var/lib/.twinlink-baseline-*.backup-*.json`) and retained after uninstall.
An older recovery command or installer may have left `baseline.json.backup-*`
inside the state directory. Use `sudo twinlink system preserve-backups --apply
--yes` to preserve a recognized private snapshot outside it before purge;
see [backup recovery](docs/operations.md#legacy-baseline-backups).
Program writes are recorded before publication, so resume can complete a
partially written launcher/runtime without accepting modified program files.
Older interrupted installations without that proof require manual recovery.
Resume does not claim package changes from the interrupted attempt;
those packages may need manual removal after uninstall. Do not delete
`/var/lib/twinlink/baseline.json`.

If Ubuntu/Debian reports that dependencies require upgrades, install the
prerequisites explicitly, then resume without automatic package changes:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends iproute2 nftables iputils-ping conntrack
sudo scripts/install.sh --resume --skip-deps
```

The Rathole bootstrap command downloads the pinned 0.5.0 release on Linux
x86_64/ARM64, or validates an executable already at `/usr/local/bin/rathole`.
It is available before pair setup/import. For a kernel-only setup, skip that
command. See [manual/offline Rathole installation](docs/operations.md#rathole-installation)
for other architectures or an already configured host.

### Optional: install the Paqet candidate

On either host, before or after pair setup:

```sh
sudo twinlink paqet install
sudo twinlink paqet install --apply --yes
```

The default output is a short installation summary. Add `--verbose` for
installation details or `--json` for structured output.

This installs the pinned [alpha.21 Linux release](https://github.com/hanselime/paqet/releases/tag/v1.0.0-alpha.21)
for x86_64/ARM64 at `/usr/local/bin/paqet`, verifying both archive and executable
checksums. It reuses an unchanged matching binary and never overwrites a different
one. **Installation does not enable Paqet traffic**: activation remains gated
pending runtime/protocol qualification. You can skip this for the Rathole walkthrough.
See [Paqet installation](docs/operations.md#paqet-installation) for custom paths and cleanup.

## 2. Create the pair on VPS1

Choose a pair name and the shared transport port once:

```sh
sudo twinlink setup --pair edge \
  --vps1 198.51.100.1 --vps2 203.0.113.2 \
  --transport-port 3456 --apply --yes
```

The pair starts **off**. Do not run `setup` independently on VPS2; it will import
VPS1's configuration in step 5.

## 3. Add the service on VPS1

This example assumes a TCP backend on VPS2 port `9000` that replies
`PONG\n` to `PING\n`. You can use the [temporary test backend](docs/operations.md#test-backend),
or replace the address, ports and probe bytes for your own application.

```sh
sudo twinlink service add echo --pair edge \
  --protocol tcp --ports 8081 \
  --backend-ports 9000 \
  --probe-request-hex 50494e470a --probe-response-hex 504f4e470a \
  --apply --yes
```

`8081` is the client-facing port. `9000` is the backend port. `3456` connects the
VPSs. A safe request/response probe is required before activation; an open port
alone does not prove delivery.

Omitting `--backend-address` means **VPS2 itself**. Rathole resolves that to
`127.0.0.1`; the kernel profile resolves it to VPS2's GRE address. To switch
between both paths, bind the backend on IPv4 `0.0.0.0:9000` or deliberately
cover both addresses. Restrict direct access to port 9000 in your existing
firewall; wildcard binding also listens on public interfaces. The temporary
loopback-only test backend works with Rathole and must be rebound for kernel
delivery. TwinLink does not change backend bindings or foreign firewall policy.

Use `--backend-address IPV4` for an explicit destination, or `service edit echo
--pair edge --backend-local` to reset the target to VPS2 itself. These edits
require the usual `--apply --yes`. New revisions use schema 3; update both peers
before exchanging them. Existing schema-2 addresses retain their meaning.

## 4. Prepare and export on VPS1

```sh
sudo twinlink config regenerate --pair edge --apply --yes
sudo twinlink pair status --pair edge
sudo twinlink pair export --pair edge --output /root/edge.p2
```

Preparation creates configs and guarded units without starting traffic.
Export **after** preparation, because preparing initial Noise keys can create a
new revision. Keep the export's returned `fingerprint` for the next step.
The bundle contains credentials; transfer it privately.

## 5. Import and prepare on VPS2

Copy `/root/edge.p2` to VPS2. Compare the export's complete SHA256 fingerprint
through an independently trusted channel, then replace `EXPECTED_SHA256` below
with that value. Use the fingerprint printed by TwinLink, not a hash of the
newline-terminated file.

```sh
sudo chmod 600 /root/edge.p2
sudo twinlink pair import --pair edge --file /root/edge.p2 \
  --expected-fingerprint EXPECTED_SHA256 --apply --yes
sudo twinlink config regenerate --pair edge --apply --yes
```

Both hosts now have the same shared configuration. Traffic is still off.

## 6. Activate with both VPSs

Check on **both** hosts:

```sh
sudo twinlink profile check direct-rathole --pair edge
```

Then begin on **VPS1 only**:

```sh
sudo twinlink profile switch direct-rathole --pair edge \
  --output /root/edge-step-01.json --apply --yes
```

This starts a multi-step exchange, not a one-command activation:

1. Read `next_host` and `next_command` in the response. `pending` / exit code 3
   means another coordination step is needed.
2. Copy the outgoing receipt privately to that host. Run its returned command,
   replacing `RECEIPT` with the incoming file and `NEXT_RECEIPT` with a **new**
   outgoing filename. Run administrative commands with `sudo`.
3. Repeat as directed, including final acknowledgements, until the transaction
   completes and neither host has a transition or `commit_pending` state.

Have receipt transfer ready before starting: preflight evidence lasts five
minutes, and target startup begins a **60-second verification budget** on each
host. Expiry withdraws unverified runtime and requires recovery. Read the
[activation and recovery guide](docs/operations.md#activation-and-recovery)
if a step fails or expires.

## 7. Verify delivery

On both VPSs:

```sh
sudo twinlink pair status --pair edge
sudo twinlink doctor --pair edge
```

Then test `198.51.100.1:8081` from an independent client using your application's
request and expected response. A committed selection or running process does
not prove public reachability. `unknown` means evidence is missing.

## Everyday use

After setup or import, `sudo twinlink menu` opens Pairing, Services, Profiles,
Status/Doctor and System/Cleanup. The CLI provides the same operations:

| Task | Command |
| --- | --- |
| Inspect configuration | `sudo twinlink config show --pair edge` |
| Watch and export diagnostics | `sudo twinlink doctor --pair edge --watch 5m --export /root/edge-report.json` |
| Stage a shared port change on VPS1 | `sudo twinlink config set transport.port 4567 --pair edge --apply --yes` |
| Begin coordinated shutdown on VPS1 | `sudo twinlink profile switch off --pair edge --output /root/edge-off-01.json --apply --yes` |
| Inspect interrupted work | `sudo twinlink recover --pair edge` |
| Preview local uninstall | `sudo twinlink uninstall --plan` |

An edit stages a new revision; it does not change the running profile. Prepare
on VPS1, export/import the edit, prepare on VPS2, then activate through the same
receipt exchange. Follow all shutdown receipts before deletion or full uninstall.

## Documentation and development

- [Operations guide](docs/operations.md): backend example, edits, switching,
  recovery, diagnostics, reboot and removal.
- [Command reference](docs/commands.md): current commands, flags and exit codes.
- [Architecture](docs/architecture.md): profiles, revisions, ownership and limits.
- [Verification](docs/verification.md): checks run and acceptance work remaining.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -q
scripts/install.sh --build-only /tmp/twinlink.pyz
```
