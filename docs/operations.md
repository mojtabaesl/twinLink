# Operations guide

[README](../README.md) · [Command reference](commands.md)

twinLink is a Python standard-library CLI for an IPv4 GRE link between two Linux VPSs, with independent kernel or rathole forwarding entries on that link. Both servers keep their own configuration. There is an interactive menu and scriptable commands; no web panel or SOCKS proxy is included.

GRE connectivity must be checked successfully before adding forwarding. A locally UP interface alone does not satisfy that requirement. Kernel mode supports TCP/UDP and ranges of up to 256 ports. Rathole mode supports single-port TCP services; UDP is deliberately rejected until a selected rathole version has passed end-to-end verification.

## Install

Use a systemd host with Python 3.9 or newer. The installer supports Debian/Ubuntu using `apt-get`, and Fedora/Rocky/Alma/RHEL using `dnf`. Suitable examples are Debian 12+, Ubuntu 22.04+ and Rocky 9+; older releases whose default Python is below 3.9 require an upgrade first. Administrative network operations require root.

```sh
sudo scripts/install.sh
sudo twinlink doctor
sudo twinlink menu
```

The installer installs `iproute2`/`iproute`, `nftables`, `conntrack`, and ICMP diagnostics. `--skip-deps` checks existing dependencies without changing packages. It builds the local checkout as a zipapp, installs a launcher at `/usr/local/bin/twinlink`, and keeps the runtime at `/usr/local/libexec/twinlink-runtime`. Managed systemd units use that runtime directly. No pip dependencies are needed.

Rathole is optional. The supported version is **0.5.0**, with TCP services and Noise encryption. The setup wizard can install it automatically. To use a separately obtained executable instead, select a trusted binary and, preferably, compare its SHA256 with a trusted checksum:

```sh
sudo scripts/install.sh --rathole /opt/rathole/rathole --rathole-sha256 TRUSTED_SHA256
sudo twinlink --rathole-binary /opt/rathole/rathole doctor
```

The source installer checks this supplied executable. Alternatively, `sudo twinlink rathole install --apply` downloads the official pinned release for Linux x86_64/ARM64, checks its version and Noise support, and installs it without overwriting an existing binary. Add `--sha256 HASH` for a trusted ZIP checksum. Pass `--rathole-binary` consistently when using a custom path. The default is `/usr/local/bin/rathole`.

Build without installing anything, including on a development Mac:

```sh
scripts/install.sh --build-only /tmp/twinlink.pyz
python3 /tmp/twinlink.pyz --help
python3 -m twinlink --help
```

## Set up GRE on both VPSs

Replace the example public addresses with addresses actually assigned to the servers. Allow IP protocol **47** (GRE, not TCP/UDP port 47) through both provider firewalls and host firewalls. Allow peer ICMP over the private GRE network for reachability checks. GRE supplies neither encryption nor authentication; its optional key separates tunnel configurations and is not a password.

On VPS1, create the desired configuration and inspect the preview:

```sh
sudo twinlink tunnel create edge --side vps1 \
  --local-public 198.51.100.10 --remote-public 203.0.113.20 \
  --local-private 10.77.0.1/30 --remote-private 10.77.0.2/30 \
  --key 424242 --mtu 1472 --ttl 64
```

Run the same command with `--apply` to confirm and commit it, or add `--apply --yes` for unattended operation. Mutations otherwise produce a preview only. Inspect the listed commands, generated files/rules, verification and rollback actions before confirming.

```sh
sudo twinlink tunnel pair-export edge
```

Copy the full `v1.` code to VPS2. The GRE code contains endpoints, both private addresses, key, MTU and TTL; it excludes forwarding secrets. On VPS2:

```sh
sudo twinlink tunnel pair-import --code 'v1.COMPLETE_CODE'
sudo twinlink tunnel pair-import --code 'v1.COMPLETE_CODE' --apply
```

Import previews the decoded parameters and swaps public endpoints, private addresses and the side. The tunnel name may be changed with `--name`. Applying GRE creation or pairing import starts/enables the tunnel, but never marks it verified. `tunnel create --disabled` instead stores a stopped, disabled tunnel. Both private addresses must be distinct RFC1918 hosts in one subnet, with no overlap with another managed tunnel or conflicting host route.

On **both** servers:

```sh
sudo twinlink tunnel start edge --apply
sudo twinlink tunnel check edge
sudo twinlink tunnel check edge --record --apply
sudo twinlink tunnel enable edge --apply
```

If VPS2 used a different name, use that local name there. `check --record --apply` records verification only after a successful GRE peer probe. Check latency, packet loss and the reported reason; diagnose a failed probe before proceeding. An interface UP flag is not proof of peer reachability. A keyed IPv4 GRE packet adds at least 28 bytes of overhead; choose MTU for the actual underlay and use diagnostics if large packets stall.

## Add and pair forwarding

VPS1 exposes the public service and VPS2 reaches the backend. Each forwarding entry has its own stable name and local lifecycle. Create the backend service before starting the forward.

For a TCP kernel forward on VPS1:

```sh
sudo twinlink forward add web --tunnel edge --mode kernel --protocol tcp \
  --bind-address 198.51.100.10 --bind-port 8080 \
  --destination-address 10.20.30.40 --destination-port 80 --apply
```

The destination must be reachable from VPS2. Applying `forward add` normally starts/enables the local entry; use `--disabled` to store it inactive while arranging peer setup. The public bind may be VPS1's primary or secondary assigned address, or `0.0.0.0`; the engine validates assignment on VPS1. Kernel mode first translates VPS1's public tuple to a dedicated relay port on VPS2's GRE address, then translates that relay tuple to the backend on VPS2. It supplies return-path NAT without installing a backend route or altering a default route. The relay port is allocated deterministically; `--relay-port` can set a nonconflicting port or equal-sized range explicitly. A range such as `8000-8010` maps to a matching destination range, or to one fixed destination port. Use `--protocol udp` for UDP kernel forwarding.

For guided Rathole with Noise, after verifying GRE on both ends, run `sudo twinlink rathole setup` on both servers. The wizard detects the VPS role and reuses saved tunnel names/endpoints. On VPS1, enter a Rathole name and connection port (default 2333), choose a known backend address or enter a different one, then supply ports such as `8080:80,8443:443`. All services share one named config/process, transport port, default token and Noise keypair. Existing configs reuse their name/port/credentials when adding services. The wizard prints one `r1.` base64 pairing code; VPS2 matches its saved tunnel and imports the whole config with no name/port/IP re-entry. A host with both roles asks which role to use. Pairing text contains service tokens; transfer it privately. Noise private keys stay on VPS1.

To merge old configs, select **Combine saved forwarding into one Rathole config** in setup, or run `sudo twinlink rathole consolidate app --tunnel edge --transport-port 2333 --apply` on VPS1. This retains service names/tokens, creates one shared Noise keypair, and transactionally removes old units/configs. Import the fresh pairing code on VPS2. Consolidation interrupts the old tunnel services until their peer settings agree. Later config updates briefly restart all services in that shared process; individual ports still support independent stop/disable/delete. Re-exporting existing settings requires no name/port prompts.

For one scriptable Rathole TCP forward instead (Noise is the default for new records):

```sh
sudo twinlink --rathole-binary /opt/rathole/rathole forward add app \
  --tunnel edge --mode rathole --protocol tcp \
  --bind-address 198.51.100.10 --bind-port 8443 \
  --destination-address 127.0.0.1 --destination-port 443 --apply
```

Rathole runs a server on VPS1 and a client on VPS2. During first setup, VPS1 can commit its private connection listener while reporting `pending_peer`; its public service listener appears after the matching VPS2 client authenticates. A committed local setup is not a claim of forwarding health. This behavior follows the [selected upstream server implementation](https://github.com/rathole-org/rathole/blob/v0.5.0/src/server.rs). Its connection listener binds only to VPS1's private GRE address. Its public service listener uses the selected bind address and port. Each entry receives a strong token and a matching service name. `--transport-port` can override the private connection port if needed. Loopback backends are available in rathole mode because the client connects locally on VPS2.

Rathole can also use `sudo twinlink rathole pair-export app` and paste the resulting code into `rathole setup` on the peer. After shared edits, generate/import a fresh code. To inspect paths without opening an editor, use `sudo twinlink rathole config app`; the default file is `/var/lib/twinlink/rathole/app.toml`, editable with `sudo vim /var/lib/twinlink/rathole/app.toml`. Manual edits are regenerated on reapply/boot restore; use `forward edit` for persistent changes.

For either mode, private file export is also available:

```sh
sudo install -d -m 700 /root/twinlink-transfer
sudo twinlink forward export web --output /root/twinlink-transfer/web.pair
sudo scp /root/twinlink-transfer/web.pair root@VPS2:/root/twinlink-transfer/web.pair
```

Create the mode-0700 transfer directory on VPS2 first. Forward export files are mode 0600 and can contain rathole tokens. Keep exports and Rathole pairing text out of public backups and version control. The wizard accepts pasted text without putting it into shell history; CLI scripts can use `rathole pair-import --file PATH` with private file permissions. Transfer `app` rather than `web` if using the rathole example. On VPS2, preview and import:

```sh
sudo twinlink forward import --file /root/twinlink-transfer/web.pair
sudo twinlink forward import --file /root/twinlink-transfer/web.pair --apply
```

The CLI matches the mirrored GRE parameters, even when the tunnel has a different local name, and validates conflicts before applying. VPS2 retains VPS1's canonical public bind address. Rathole service names must remain identical on both servers. Import is stopped by default. Start on VPS1, then VPS2, and enable on both when ready for reboot persistence. For rathole, finish by checking both hosts after the client connects:

```sh
sudo twinlink forward start web --apply
sudo twinlink forward check web
sudo twinlink forward enable web --apply
```

Test from a third host against VPS1's public address. Compare the response with the actual target service on VPS2; process status alone does not establish end-to-end success. Remove transfer files when no longer needed and retain secure backups of state if recovery is required.

## Daily operation

```sh
sudo twinlink status
sudo twinlink tunnel list
sudo twinlink tunnel show edge
sudo twinlink tunnel diagnose edge
sudo twinlink forward list
sudo twinlink forward show web
sudo twinlink forward diagnose web
sudo twinlink --json tunnel check edge
sudo twinlink --json forward check web
```

Both `tunnel` and `forward` support `edit`, `enable`, `disable`, `start`, `stop`, `restart`, `reapply`, `check`, `diagnose`, and `delete`. Enablement controls reboot intent; start/stop controls current runtime intent. Disable also stops public exposure. Checks read actual kernel interfaces/addresses, managed rules, sockets, processes and peer probes rather than trusting saved operational flags.

Examples:

```sh
sudo twinlink forward edit web --destination-port 8081 --apply
sudo twinlink forward export web --output /root/twinlink-transfer/web-v2.pair
sudo twinlink forward disable web --apply
sudo twinlink forward restart web --apply
sudo twinlink forward reapply web --apply
sudo twinlink forward delete web --apply
sudo twinlink tunnel delete edge --no-cascade --apply
sudo twinlink tunnel delete edge --cascade --apply
```

After any edit to shared forwarding settings, transfer a fresh export and import it on the other server. Shared edits increment the revision and stop/disable the edited local forward. After importing, enable/start it on both servers again. Revisions identify stale transfers; the CLI cannot remotely update the peer. Kernel relay ports and rathole tokens must agree. Coordinate edits during a maintenance window because existing connections can be terminated. Disabling/deleting a kernel entry also removes its matching conntrack flows so existing NAT flows cannot keep the old public exposure alive. For shared GRE edits, transfer a fresh tunnel pairing code and use `tunnel pair-import --replace` only after inspecting its preview; replacing a tunnel stops its dependent entries.

Tunnel deletion lists dependencies. When any exist, choose `--no-cascade` to refuse their deletion or `--cascade` to explicitly include them. Deletion removes only owned interfaces, files, rules and units, and reports cleanup failures.

## Drift and recovery

Use `check` for status and `diagnose` for evidence such as peer ping, TCP destination reachability, path MTU commands, generated configuration and systemd logs. Forwarding health distinguishes GRE failure, rathole connection/process failure, missing public listeners or rules, and destination failure. A destination probe can fail because of an intentional backend firewall policy; inspect the specific reason and test the intended traffic from a third host.

```sh
sudo twinlink tunnel reapply edge --apply
sudo twinlink forward reapply web --apply
sudo twinlink recover --apply
```

Reapply repairs desired configuration drift. An unfinished transaction blocks subsequent mutation; `recover` uses its private journal to restore the prior state. If rollback has partial failures, inspect the reported command and concrete repair instructions, retain the journal, repair the underlying problem and rerun recovery. Do not delete the journal to hide an incomplete network change.

State and rollback data live in `/var/lib/twinlink` (0700), with `state.json`, transaction journals, generated rules and rathole secrets restricted to 0600. `--state-dir`, `--unit-dir`, `--runtime-path`, and `--rathole-binary` are global options. A state directory represents one managed installation; do not run independent state directories against the same host namespace because the application owns one dedicated `ip twinlink` nftables table.

## Uninstall

Remove the user-facing program while keeping managed networking and reboot persistence:

```sh
sudo scripts/uninstall.sh
```

This removes `/usr/local/bin/twinlink`. When managed records or owned units exist it retains the runtime, state, secrets and units, so the units' executable remains available. Reinstall to restore the launcher, or invoke the retained runtime directly. The uninstaller reports everything retained. Dependencies and separately installed rathole binaries are retained.

Explicitly remove managed tunnels and forwards, then remove the program:

```sh
sudo scripts/uninstall.sh --purge-managed --cascade
# Unattended, after reviewing the intended removal:
sudo scripts/uninstall.sh --purge-managed --cascade --yes
```

The purge runs the normal preview/apply/verify transaction and requires the cascade choice. Program files remain if resource removal fails. State/backups remain for review. Installation manifests prevent overwriting or removing foreign or modified program files.

## Verification

Run unit tests without root:

```sh
python3 -m unittest discover -s tests -v
```

Validation and pairing unit tests cover private subnet/endpoint conflicts, SSH and wildcard/public/relay port conflicts including disabled reservations, malformed and oversized pairing codes, exact peer swapping, strong tokens, revision updates and stale imports. Other test modules exercise rendered plans, ownership and rollback using a fake host. These are not substitutes for real packet delivery tests.

Linux network namespace integration tests require root, GRE support, nftables, conntrack, iproute2 and ICMP tools. Rathole coverage additionally requires a trusted rathole executable:

```sh
sudo -E env TWINLINK_INTEGRATION=1 \
  TWINLINK_RATHOLE_BINARY=/opt/rathole/rathole \
  python3 -m unittest discover -s tests/integration -v
```

Inspect skip messages if a dependency or selected executable is unavailable. The test-only `--no-systemd` global option requires `TWINLINK_TESTING=1`; it must not be used for production reboot management.

The development environment is macOS, so Linux namespace packet delivery, systemd restart and real reboot checks cannot be claimed from tests run here. Before production use, run the Linux suite and check both real VPSs after a reboot: peer reachability, each forwarding mode from an external host, edit/re-pair, disable/delete port closure, drift/reapply, failure rollback, and service restart recovery. Provider GRE filtering and underlay MTU require real environment validation. See [architecture](architecture.md) for ownership and recovery boundaries.
