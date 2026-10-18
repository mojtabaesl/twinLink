# Command reference

[README](../README.md) · [Operations guide](operations.md)

These commands manage pair configurations and profiles in TwinLink 2.0.0a1.
Run administrative operations with `sudo`. Examples use pair `edge`; specify
`--pair ID` whenever there is more than one pair.

## Preview, apply and output

Mutations preview by default. Add `--apply` to confirm interactively, or
`--apply --yes` to execute without a prompt. Exports write immediately and require
new filenames; TwinLink does not overwrite existing transfer/report files.

```sh
sudo twinlink config set transport.port 4567 --pair edge
sudo twinlink config set transport.port 4567 --pair edge --apply --yes

twinlink --help
twinlink profile switch --help
twinlink service add --help
twinlink --version
```

Pair/profile commands emit versioned JSON with `schema_version`, `action` and
`status`. Read `next_host`, `next_command`, `error` and `commit_pending` when
present. Do not expect a short human summary or a bare pairing code. Exporting
without `--output` places the secret bundle in the JSON response.

| Exit code | Meaning |
| --- | --- |
| 0 | Command completed, successful check, or successful preview |
| 1 | Operation or delivery check failed |
| 2 | Invalid input or incompatible configuration |
| 3 | Pending coordination or unknown evidence |
| 4 | Ownership conflict or recovery required |

A successful preview does not mean changes were applied. A local preflight
success does not mean the peer is ready or Internet delivery works.

## Global paths

Place global options **before** the command group. Use the same paths on later
invocations for that installation.

| Option | Default |
| --- | --- |
| `--state-dir PATH` | `/var/lib/twinlink` |
| `--unit-dir PATH` | `/etc/systemd/system` |
| `--runtime-path PATH` | Installed launcher supplies its persistent runtime path |
| `--rathole-binary PATH` | `/usr/local/bin/rathole` |
| `--paqet-binary PATH` | `/usr/local/bin/paqet` |

```sh
sudo twinlink --rathole-binary /opt/rathole/rathole config regenerate --pair edge
```

That example is a preview; add apply flags when ready. `--no-systemd` is reserved
for isolated tests, not server operation.

## Setup and pairing

On a fresh host, `sudo twinlink rathole install --apply --yes` downloads the
pinned Rathole release (or validates an existing binary). Run it **before**
pair setup/import. The bootstrap command is disabled once pair state is in use;
see [manual installation](operations.md#rathole-installation) for that case.
An optional `--sha256 HASH` checks a trusted release archive checksum.

Paqet has a separate installer, available before or after pair setup:

```sh
sudo twinlink paqet install
sudo twinlink paqet install --apply --yes
sudo twinlink paqet install --apply --yes --verbose
sudo twinlink --paqet-binary /opt/paqet/paqet paqet install --apply --yes
```

The custom parent directory must already exist. It downloads only the pinned
alpha.21 Linux x86_64/ARM64 release, verifies built-in archive and binary hashes,
and never replaces a different executable. Optional `--sha256 HASH` must match
the built-in archive pin; it cannot override it. Installation records ownership
for conditional cleanup but does not qualify or activate the Paqet profile.

Paqet installation prints a short summary by default, like Rathole. Add
`--verbose` for release, checksum, and installation details, or `--json` for
the versioned JSON document used by scripts.

| Command | Purpose |
| --- | --- |
| `setup --pair ID --vps1 IPV4 --vps2 IPV4 --transport-port PORT` | Create shared settings on VPS1 with runtime off. |
| `setup` | Open the interactive pair wizard in a terminal. |
| `setup --file PATH` | Use a private complete shared revision JSON file. |
| `pair status --pair ID` | Show local role, active/staged revisions, transitions and profile compatibility. |
| `pair export --pair ID --output PATH` | On VPS1, export the latest staged revision and its fingerprint. Contains secrets. |
| `pair export --pair ID --revision N --output PATH` | Export a retained intermediate revision. |
| `pair import --pair ID --file PATH --expected-fingerprint SHA256` | Bootstrap VPS2 using a privately transferred bundle and independently verified fingerprint. |
| `pair import --pair ID --file PATH` | Import an established pair's next revision with its stored management key. |
| `pair import --pair ID --file -` | Read a bundle from stdin. Omit `--file` for hidden paste. |
| `pair delete --pair ID` | After coordinated off, remove that pair's unchanged owned resources and private history. |

Bundle files must be private (mode 0600). Read the `fingerprint` field returned
by export; a hash of a file with an added newline is a different value. Never
put a secret bundle in command arguments. New output files need an existing
parent directory.

## Services and shared edits

VPS1 authors edits. Add/edit/delete stages a new revision without switching the
active one. `service list` and `config show` describe staged settings.

| Command | Purpose |
| --- | --- |
| `service list --pair ID` | List configured services. |
| `service add NAME --pair ID [options]` | Add a mapping. |
| `service edit NAME --pair ID [options]` | Change selected mapping/probe fields. |
| `service delete NAME --pair ID` | Remove a mapping from the next revision. |
| `config show --pair ID` | Inspect canonical shared settings. |
| `config set FIELD VALUE --pair ID` | Stage a shared field change. |
| `config regenerate --pair ID` | Refresh local facts/configs, pin binaries and prepare guarded units. Does not start traffic. |
| `system preserve-backups` | Preview preservation of validated legacy baseline snapshots outside the state directory; add `--apply --yes` to execute. See [backup recovery](operations.md#legacy-baseline-backups). |

| Service option | Meaning |
| --- | --- |
| `--bind IPV4` | VPS1 bind address; defaults to the pair's VPS1 public address for new services. |
| `--protocol tcp\|udp` | Defaults to TCP; Rathole profiles accept TCP only. |
| `--ports PORT_OR_RANGE` | Public port or inclusive range, such as `8081-8082`. |
| `--backend-address IPV4` | Explicit backend reachable from VPS2. Explicit loopback is incompatible with kernel DNAT. |
| `--backend-local` | Target VPS2 itself; mutually exclusive with `--backend-address`. Default for add; explicit reset for edit. |
| `--backend-ports PORT_OR_RANGE` | Equal-width range, or one fixed backend port. |
| `--probe-request-hex HEX` | Safe application request as hex bytes. |
| `--probe-response-hex HEX` | Expected application response as hex bytes. |

Specify both probe fields together. Every service needs a safe exchange before
activation. Unsupported mappings make the whole profile incompatible.
Omitting both target options on edit preserves the saved intent/address.
Add previews show the effective target for every profile. VPS2-local resolves
to its GRE address for kernel delivery and IPv4 loopback for proxy profiles.
See [backend bindings](operations.md#backend-intent-and-bindings) before switching.
`config set` accepts `transport.port`, `gre.mtu`, `gre.ttl`, `gre.key`,
`gre.addresses`, `gre.addresses.vps1`, `gre.addresses.vps2`,
`public_endpoints.vps1` and `public_endpoints.vps2`. To change the GRE subnet,
set both addresses in one revision:

```sh
sudo twinlink config set gre.addresses '{"vps1":"10.78.0.1/30","vps2":"10.78.0.2/30"}' --pair edge --apply --yes
```

## Profile lifecycle and recovery

Targets are `direct-rathole`, `gre-rathole`, `gre-kernel`, `direct-paqet` and `off`.
Paqet activation is currently gated. Begin activation on VPS1 and follow the
returned host/command sequence; see [activation and recovery](operations.md#activation-and-recovery).

| Command | Purpose |
| --- | --- |
| `profile list --pair ID` | List profile compatibility and selection information. |
| `profile check TARGET --pair ID` | Read-only local preflight, including configured backend probes on VPS2. |
| `profile switch TARGET --pair ID --output PATH` | Begin or resume a coordinated switch, including off. |
| `profile restart --pair ID --output PATH` | Coordinate restart of the active revision/profile. |
| `profile reapply --pair ID --output PATH` | Coordinate repair of the active revision/profile. |
| `recover --pair ID` | Inspect interrupted work and recovery instructions. |
| `recover --pair ID --rollback --output PATH` | Begin coordinated withdrawal and restoration of the saved selection. |
| `recover --pair ID --cancel-preflight` | Cancel only non-disruptive local preflight; repeat on the peer. |

Switch/restart/reapply and rollback continuations accept `--transaction ID`,
`--step NAME`, `--receipt-file PATH` and `--output NEW_PATH`. Switch/restart/reapply
also accept `--revision N`. Use the returned commands to keep these values
consistent. `--refresh-receipt` revalidates and renews the last completed local
phase; it does not reset preflight or verification deadlines.

## Diagnostics and maintenance

| Command | Purpose |
| --- | --- |
| `status` | Summarize all pairs; selection is separate from delivery health. |
| `menu` | After pair setup/import, open the pair/profile management menu. |
| `doctor --pair ID` | Collect quick local resource and application evidence. |
| `doctor --pair ID --deep` | Use the deeper collection budget. |
| `doctor --pair ID --watch 5m --interval 1 --export PATH` | Sample and export a private report. |
| `doctor --preview` | Show budgets without collecting evidence. |
| `doctor --pair ID --redaction secrets --export PATH` | Retain diagnostic identities/ports while removing credentials. |
| `doctor --merge A B --export PATH` | Merge two private secrets-level reports; share redaction is the default output. |
| `doctor --pair ID --redaction secrets --compare OLD` | Compare a prior private secrets-level report with current private evidence. |
| `logs --pair ID --limit 200` | Read bounded, credential-scrubbed process logs. |
| `system changes` | Show redacted ownership records and conflicts. |
| `system restore` | Conditionally restore owned settings after every pair is off. |
| `uninstall --plan` | Inspect local removal requirements. |
| `uninstall --purge` | After every pair completes coordinated off, remove owned resources and the authenticated local installation. |

Add apply flags to restoration, deletion and removal when ready. Scope and
conflict handling are explained in [removal](operations.md#removal).

Opt-in capture adds `--capture --capture-interface NIC --capture-peer IPV4
--capture-port PORT`, optionally `--capture-direction in|out|inout`. It records
bounded TCP metadata, not payload. Without the selectors, capture is rejected.
