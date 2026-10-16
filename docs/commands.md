# Command reference

[README](../README.md) · [Operations guide](operations.md)

Run administrative commands with `sudo`. Examples use tunnel `edge` and forwarding entry `web`. Replace names, addresses, ports, and paths as needed.

## Applying changes and getting help

Configuration and lifecycle changes **preview by default**. Review the plan, repeat with `--apply`, and type `apply` when prompted. Scripts require `--apply --yes`. Exports write their output immediately; they do not use these flags.

```sh
sudo twinlink forward stop web                 # Preview
sudo twinlink forward stop web --apply         # Confirm interactively
sudo twinlink forward stop web --apply --yes   # Apply without a prompt

twinlink --help
twinlink tunnel --help
twinlink forward add --help
twinlink --version
```

## General commands

| Command | Explanation |
| --- | --- |
| `twinlink menu` | Open the two main workflows: GRE tunnels and Port forwarding (Kernel or Rathole). Health, dependencies, recovery and expert commands are under System tools. |
| `twinlink doctor` | Report networking dependencies, platform, systemd availability, and the configured rathole path. |
| `twinlink status` | Show saved configuration and observed health for every managed tunnel and forward, including unfinished-transaction status. |
| `twinlink recover` | Preview rollback of an interrupted transaction. Use `--apply` to restore the journal's prior state. |
| `twinlink uninstall` | Show removal guidance and managed resource names. |
| `twinlink uninstall --purge-managed --cascade` | Preview deletion of all managed tunnels and forwards. Add `--apply` to remove resources; use the uninstall script to remove program files. |

## Tunnel commands

| Command | Explanation |
| --- | --- |
| `twinlink tunnel create NAME [options]` | Define a GRE tunnel. Applying normally starts it and enables it at boot; `--disabled` stores it stopped and disabled. |
| `twinlink tunnel edit NAME [options]` | Change selected tunnel fields. Shared changes clear verification and stop/disable dependent forwards; pair and verify again. |
| `twinlink tunnel list` | List tunnel configuration and live status. |
| `twinlink tunnel show NAME` | Inspect one tunnel's configuration and live status. |
| `twinlink tunnel check NAME` | Check kernel configuration and probe the GRE peer. |
| `twinlink tunnel check NAME --record --apply` | Record verification after the peer probe and kernel configuration checks pass. Required before adding forwarding. |
| `twinlink tunnel diagnose NAME` | Gather peer, path MTU, and service diagnostics. |
| `twinlink tunnel pair-export NAME` | Print the GRE pairing code; includes tunnel settings, excludes forwarding credentials. |
| `twinlink tunnel pair-import --code CODE` | Decode a code, swap endpoints and side, and preview the peer tunnel. Applying starts/enables it but leaves it unverified. |
| `twinlink tunnel pair-import --file PATH` | Read the pairing code from a file instead. |

Tunnel creation requires `--side`, both public addresses, and both private addresses:

```sh
sudo twinlink tunnel create edge --side vps1 \
  --local-public 198.51.100.10 --remote-public 203.0.113.20 \
  --local-private 10.77.0.1/30 --remote-private 10.77.0.2/30 \
  --key 424242 --mtu 1472 --ttl 64 --apply
```

| Create/edit option | Explanation |
| --- | --- |
| `--side vps1\|vps2` | Local role: public entry server or backend-side server. |
| `--local-public ADDRESS` | This server's public IPv4 address. |
| `--remote-public ADDRESS` | Peer server's public IPv4 address. |
| `--local-private ADDRESS/PREFIX` | This server's private GRE address with subnet prefix. |
| `--remote-private ADDRESS/PREFIX` | Peer GRE address; distinct RFC1918 host in the same subnet. |
| `--key INTEGER` | Optional GRE key shared by both ends; does not provide authentication. |
| `--mtu INTEGER` | GRE MTU; defaults to 1472 with a key or 1476 without one. Adjust for the underlay. |
| `--ttl INTEGER` | Outer packet TTL; default 64. |
| `--disabled` | Create only: store without starting or enabling at boot. |
| `--clear-key` | Edit only: remove the GRE key. |

Pair import accepts `--name NAME` to choose a local name and `--replace` to replace an existing tunnel. Replacement stops/disables its dependent forwarding entries. Inspect the preview first.

## Forwarding commands

Kernel and Rathole are two methods under the same `forward` command group. After GRE is verified, use `sudo twinlink forward setup` on both servers. VPS1 chooses a method; VPS2 detects it from the pasted code. `--mode kernel` or `--mode rathole` preselects the method on VPS1. Setup always previews and asks for apply confirmation.

| Command | Explanation |
| --- | --- |
| `twinlink forward setup [--mode kernel\|rathole]` | Guided forwarding setup. Reuses saved tunnel roles/endpoints; asks for method-specific ports/backend on VPS1, or pasted pairing text/private file on VPS2. Installs Rathole only when needed. |
| `twinlink forward menu` | Open forwarding management directly, including both methods, pairing and Rathole config paths. |
| `twinlink forward add NAME --mode kernel [options]` | Add Kernel TCP/UDP forwarding attached to verified GRE. Applying normally starts/enables it and prints an `f1.` pairing code; `--disabled` stores it inactive. |
| `twinlink forward add NAME --mode rathole --tunnel TUNNEL --ports PORTS` | Add TCP services with Noise in one shared config/process. Apply prints one `r1.` pairing code for the whole config. |
| `twinlink forward pair-export NAME [NAME ...]` | Print an `f1.` code for one Kernel entry, or an `r1.` code for Rathole services/groups. Selecting a grouped Rathole service includes its whole config. Mixed methods are exported separately. |
| `twinlink forward pair-import --code CODE` | Detect either code and preview its matching peer configuration. `--apply` stores stopped; `--enable --apply` also starts/enables it. Saved verified GRE is required. |
| `twinlink forward pair-import --file PATH` | Read either code from a private mode-0600 file. Accepts `--enable`. |
| `twinlink forward edit NAME [options]` | Change selected settings. Shared edits increment the revision and stop/disable the entry; export/import again before enabling both peers. |
| `twinlink forward list` | List forwarding configuration and live status. |
| `twinlink forward show NAME` | Inspect one forwarding entry. |
| `twinlink forward check NAME` | Check GRE, mode-specific runtime/rules/listeners, and destination reachability. Test real traffic separately. |
| `twinlink forward diagnose NAME` | Gather forwarding diagnostics, including service/configuration evidence. |
| `twinlink forward export NAME --output PATH` | Write a new mode-0600 transfer file, including a rathole token when applicable. Parent directory must exist; existing files are not overwritten. |
| `twinlink forward import --file PATH` | Preview the peer configuration matched to a verified mirrored tunnel. Applying imports it stopped. |

Example kernel forward:

```sh
sudo twinlink forward add web --tunnel edge --mode kernel --protocol tcp \
  --bind-address 198.51.100.10 --bind-port 8080 \
  --destination-address 10.20.30.40 --destination-port 80 --apply
```

| Add/edit option | Explanation |
| --- | --- |
| `--tunnel NAME` | Required for add: local verified GRE tunnel. Association cannot change through edit. |
| `--mode kernel\|rathole` | Required for add: forwarding engine. Mode cannot change through edit. |
| `--protocol tcp\|udp` | Transport protocol; defaults to TCP. Rathole accepts TCP only. |
| `--bind-address ADDRESS` | VPS1 public IPv4 address or `0.0.0.0`; defaults to VPS1's configured public tunnel endpoint. |
| `--bind-port PORT_OR_RANGE` | Exposed public port, required unless using Rathole `--ports`. Kernel ranges support up to 256 ports; individual Rathole entries accept one port. |
| `--destination-address ADDRESS` | Backend IPv4 reachable from VPS2. Required for single/range adds; Rathole `--ports` defaults to `127.0.0.1`. Loopback is supported in Rathole mode. |
| `--destination-port PORT_OR_RANGE` | Backend port, required unless using Rathole `--ports`. Kernel ranges must match the bind width, or use one fixed destination port. |
| `--ports PUBLIC:BACKEND,...` | Rathole add only: create services in the named shared config. Cannot combine with `--bind-port`, `--destination-port`, `--relay-port` or `--rathole-group`. Uses TCP and Noise. |
| `--relay-port PORT_OR_RANGE` | Kernel only: override the automatically allocated private relay port/range. Width must match the bind range. |
| `--transport-port PORT` | Rathole only: connection port. With `--ports`, defaults to 2333 for a new config or the saved group port when adding services. Legacy individual adds allocate it automatically. |
| `--rathole-transport noise\|tcp` | Rathole only: new CLI forwards default to Noise; existing records retain TCP until explicitly changed on VPS1 and paired again. |
| `--disabled` | Add only: store without starting or enabling at boot. |

Forward import accepts `--name NAME` for a local name override. Rathole service names must remain identical on both hosts. Transfer files must have private permissions (`chmod 600 PATH`).

## Rathole installation, Noise and base64 pairing

All Rathole forwards run over a verified GRE tunnel. Create Noise forwards on VPS1, then import the pairing text on VPS2. New Noise credentials are generated with the native `rathole --genkey`; tokens are generated automatically. Server private keys are kept only on VPS1.

| Command | Explanation |
| --- | --- |
| `twinlink forward setup --mode rathole` | Enter the shared setup flow with Rathole preselected. Reuse saved roles/endpoints; ask for a new config's name/port and forwarding services. Repeat runs can add, export or consolidate. Available under Main menu → Port forwarding → Set up forwarding. |
| `twinlink forward install-rathole` | Preview installation of the official pinned 0.5.0 Linux x86_64/ARM64 release at `--rathole-binary`. Add `--apply` to download/install; compatible binaries are reused. |
| `twinlink forward install-rathole --sha256 HASH --apply` | Verify the downloaded ZIP archive against an optional trusted SHA256. This differs from the source installer's executable checksum. |
| `twinlink forward add NAME --mode rathole --tunnel TUNNEL --ports PORTS` | Preview Noise services in the named shared config/process on VPS1. `--transport-port PORT` chooses its connection port (default 2333 for new configs, saved port for existing ones). Add `--apply` to start/enable; successful apply prints a pairing code for the whole config. |
| `twinlink forward consolidate NAME --tunnel TUNNEL --transport-port PORT` | Preview merging all Rathole forwards on this tunnel into one named config/process. Preserves service names/tokens, shares a fresh Noise keypair and port, increments revisions, and removes obsolete configs/units. Apply on VPS1, then import the new code on VPS2. |
| `twinlink forward pair-export NAME [NAME ...]` | Print one `r1.` base64 code for up to 64 existing services. Accepts Rathole group names or forwarding names; selecting a group member includes its entire group. Excludes server private keys. |
| `twinlink forward pair-import --code CODE` | Decode and preview the peer forwards. Add `--apply` to store stopped, or `--enable --apply` to start and enable at boot. Use the wizard to paste without putting credentials in shell history. |
| `twinlink forward pair-import --file PATH` | Read pairing text from a private mode-0600 file instead. |
| `twinlink forward config NAME` | Print the exact TOML path, quoted vim/nano commands and restart command. Never opens an editor. |

Batch options: `--destination-address` defaults to `127.0.0.1` on VPS2; `--bind-address` defaults to VPS1's public endpoint; `--disabled` stores stopped/disabled forwards. `--ports 8080:80,8443:443,9000` creates services named `NAME-8080`, `NAME-8443`, and `NAME-9000`, including the port suffix for a single mapping. Long group names are truncated to 42 characters in generated service names. All services use `NAME.toml` and `twinlink-rathole-NAME.service`. Port/name conflicts fail the whole batch before applying. Separate GRE peers require separate named configurations.

The common interactive wizard selects a sole running/verified GRE tunnel automatically and uses its saved role and public/private addresses. Multiple VPS1 tunnels are listed by name and peer IP for numbered selection. VPS2's pairing text identifies its tunnel and method without a selector. A role selector is needed only if eligible saved tunnels include both roles. Backend choices include saved forwarding destinations and VPS2's GRE/public IP; Rathole also offers loopback. A new Rathole config asks for its name and connection port; an existing config reuses those values. If there are no eligible tunnels, setup prints repair commands before attempting installation.

```sh
# On both hosts, install once (the wizard also handles this):
sudo twinlink forward install-rathole --apply

# On VPS1, using an already verified GRE tunnel:
sudo twinlink forward add app --mode rathole --tunnel edge \
  --transport-port 2333 --destination-address 127.0.0.1 \
  --ports 8080:80,8443:443 --apply

# Copy the pairing code from the result; on VPS2 paste it into this wizard:
sudo twinlink forward setup

# Re-export after shared edits:
sudo twinlink forward pair-export app
sudo twinlink forward config app

# Combine an older per-port setup, then import its fresh code on VPS2:
sudo twinlink forward consolidate app --tunnel edge --transport-port 2333 --apply
```

The pairing text contains authentication tokens. Base64 and the corruption checksum provide no confidentiality or sender authentication. Transfer it privately. Routine status, diagnostics and previews redact tokens/private keys; setup results and explicit pairing exports intentionally show the transfer code.

Default generated TOML path: `/var/lib/twinlink/rathole/NAME.toml`. `sudo vim /var/lib/twinlink/rathole/NAME.toml` edits it manually; reapply/boot restore regenerate it from saved state. For persistent forwarding changes, use `forward edit SERVICE ... --apply`, re-export/import and enable on both sides. Each service can stop/disable/delete independently; its section is omitted while siblings remain active. Config changes restart the shared process and briefly reconnect all its services. Shared name/connection-port/Noise changes use `forward consolidate` on VPS1, then pairing again. Existing legacy records retain their separate configs until consolidated.

### Existing Rathole commands

The `twinlink rathole` commands remain compatible for existing scripts: `setup` enters `forward setup --mode rathole`, `install` corresponds to `forward install-rathole`, and `add` corresponds to `forward add --mode rathole --ports …`. `config`, `consolidate`, `pair-export` and `pair-import` also remain available under that older group. New workflows use `forward` for both methods.

## Lifecycle commands

These actions work with **both** `tunnel` and `forward`:

```sh
sudo twinlink tunnel start edge --apply
sudo twinlink forward disable web --apply
```

| Action | Explanation |
| --- | --- |
| `start NAME` | Start now, keeping the existing boot enablement setting. |
| `stop NAME` | Stop now, keeping the existing boot enablement setting. Stopping a tunnel also stops its dependent forwards. |
| `enable NAME` | Start now and enable at boot. Enabling a tunnel does not automatically start its stopped forwards. |
| `disable NAME` | Stop now and disable at boot. Disabling a tunnel also stops/disables its dependent forwards. |
| `restart NAME` | Force runtime reconciliation and leave the resource running, keeping boot enablement unchanged. |
| `reapply NAME` | Reconcile desired configuration to repair drift, keeping saved runtime/boot intent. |
| `delete NAME` | Remove the managed resource and its owned configuration. Tunnel dependencies require an explicit cascade choice. |

Tunnel deletion choices:

```sh
# Refuse deletion if any forwards depend on this tunnel
sudo twinlink tunnel delete edge --no-cascade --apply

# Remove the tunnel and all its dependent forwards
sudo twinlink tunnel delete edge --cascade --apply
```

## Global and inspection options

Place global options **before** the command group:

```sh
sudo twinlink --json forward check web
sudo twinlink --rathole-binary /opt/rathole/rathole forward start app --apply
```

| Option | Explanation |
| --- | --- |
| `--json` | Machine-readable output with secrets redacted; also accepted on public subcommands. |
| `--state-dir PATH` | State, secrets, and journals; default `/var/lib/twinlink`. Use one managed installation per host namespace. |
| `--unit-dir PATH` | Managed systemd unit directory; default `/etc/systemd/system`. |
| `--runtime-path PATH` | Absolute runtime path used by units; default `/usr/local/libexec/twinlink-runtime`. |
| `--rathole-binary PATH` | Supplied rathole 0.5.0 executable; default `/usr/local/bin/rathole`. |
| `--version` | Print the CLI version and exit. |
| `--help` | Show usage for the selected command. |

`list` and `show` accept `--no-probe` to skip the peer probe; reachability then remains unknown. Mutations accept `--apply` and `--yes` as described above. The hidden `--no-systemd` option is reserved for isolated integration tests with `TWINLINK_TESTING=1`.

## Installer and uninstaller

Run scripts from the repository checkout.

| Command or option | Explanation |
| --- | --- |
| `sudo scripts/install.sh` | Install dependencies, build the runtime, and install the command launcher. |
| `scripts/install.sh --build-only PATH` | Build a standalone zipapp without installing; no root required. |
| `sudo scripts/install.sh --skip-deps` | Check existing dependencies without package-manager changes. |
| `sudo scripts/install.sh --rathole PATH` | Check a separately supplied rathole executable. |
| `--rathole-sha256 HASH` | Installer: verify the supplied rathole executable against a trusted checksum. |
| `--prefix PATH` | Installer/uninstaller: choose the installation prefix; default `/usr/local`. |
| `sudo scripts/uninstall.sh` | Remove the launcher, retaining runtime/services when managed resources remain. |
| `sudo scripts/uninstall.sh --purge-managed --cascade` | Remove managed resources transactionally, then remove program files. State/backups and external dependencies remain. |
| `--yes` | Uninstaller: skip the managed purge confirmation. |
| `--state-dir PATH`, `--unit-dir PATH` | Uninstaller: locate custom state and managed unit directories. |

## Exit codes and internal commands

| Code | Meaning |
| --- | --- |
| `0` | Command succeeded; for health checks, the resource is up. |
| `1` | Validation, host/dependency, state, or application error. |
| `2` | A `check` reported health other than up, or argparse rejected CLI syntax. |
| `130` | Interrupted by the user. |

`twinlink internal restore`, `twinlink internal tunnel-up NAME`, and `twinlink internal tunnel-down NAME` are callbacks for managed systemd units. Use the public lifecycle commands for routine operation.

## Terminal output

Commands show concise human summaries by default, including when redirected.
Use `--verbose` for detailed, redacted JSON-style payloads, or `--json` for
script-compatible JSON. `--json` takes precedence when both are supplied.
Both flags work before the command group or after any public leaf command:

```sh
sudo twinlink --verbose status
sudo twinlink tunnel show edge --verbose
sudo twinlink forward check web --json --verbose
```

Titles and health words use color only on a terminal. Redirecting output,
setting a nonempty `NO_COLOR`, or using `TERM=dumb` disables color. Detailed
payloads and pairing-code lines are always uncolored. Default `pair-export`
prints only the complete pairing code, suitable for piping.

```text
Preview: create tunnel edge
  edge | Peer: 203.0.113.2 | GRE: 10.77.0.1/30 -> 10.77.0.2/30
  Start now; enable at boot
No changes applied. Repeat with --apply.
```

An applied result confirms configuration commit; use resource checks and an
external traffic test to verify connectivity. Forward setup prints a complete
pairing code on its own line followed by the peer setup command.
