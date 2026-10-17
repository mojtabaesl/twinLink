# Operations guide

[README](../README.md) · [Command reference](commands.md) · [Verification](verification.md)

Use the [README walkthrough](../README.md#1-install-on-both-vpss) for a new pair.
The order is: install both hosts → configure services on VPS1 → prepare VPS1 →
export/import → prepare VPS2 → coordinate activation → verify real delivery.
This guide covers the details needed after that walkthrough.

## Rathole installation

The README installs Rathole before pair creation/import, while the bootstrap
installer command is available. It targets Linux x86_64/ARM64 and checks version
0.5.0 and native Noise key generation. Supply `--sha256 HASH` when you have an
independently trusted release **archive** checksum.

For an offline host, another architecture or an already configured pair, obtain
a trusted Rathole 0.5.0 executable with Noise support separately. To place it at
the default path (replace the source path):

```sh
sudo install -m 755 /path/to/rathole /usr/local/bin/rathole
/usr/local/bin/rathole --version
```

The source installer can validate an existing executable with
`sudo scripts/install.sh --rathole /usr/local/bin/rathole`, optionally adding
`--rathole-sha256 HASH` for its **executable** checksum. This option does not
download or copy the binary. A custom executable path requires the global
`--rathole-binary PATH` option on subsequent commands.

Replacing a prepared binary invalidates its pin. For an existing active pair,
stage a new revision, prepare and transfer it, then coordinate activation as
described below; changing the executable alone does not authorize a restart.

## Paqet installation

Paqet installation is optional and does not activate a profile. On each host
where you want the candidate binary:

```sh
sudo twinlink paqet install
sudo twinlink paqet install --apply --yes
```

The preview performs no download or native execution. Apply requires Linux/root,
downloads only alpha.21 for x86_64/ARM64, and verifies the pinned archive and
executable hashes before running `paqet version`. The installer reads one bounded
regular executable from the tar archive; it does not unpack upstream configs,
create services or change firewall settings. Existing different executables and
symlinks are refused, not overwritten.

The default destination is `/usr/local/bin/paqet`. For a custom destination, put
`--paqet-binary /absolute/path/paqet` before `paqet install`; the parent directory
must exist. Optional `--sha256 HASH` confirms the built-in archive checksum and
cannot substitute another release. Source pins come from the
[pinned upstream release](https://github.com/hanselime/paqet/releases/tag/v1.0.0-alpha.21).

New installations are journaled with binary fingerprints for conditional removal.
Retry the same install after interruption. A matching pre-existing executable is
validated and reused without being adopted; edited binaries are preserved as
cleanup conflicts. Full local uninstall removes the unchanged binary installed
by TwinLink. The runtime binary qualification registry and TCP/UDP qualification
gates remain unchanged: installing the candidate does not make `direct-paqet`
activatable.

## Test backend

The README's TCP example uses `127.0.0.1:9000` on VPS2. For a disposable test,
run this on **VPS2 in a separate terminal** and keep it running during preflight,
activation and doctor checks:

```sh
python3 - <<'PYTHON'
import socketserver

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        if self.rfile.readline(16) == b"PING\n":
            self.wfile.write(b"PONG\n")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", 9000), Handler) as server:
    print("Test backend listening on 127.0.0.1:9000", flush=True)
    server.serve_forever()
PYTHON
```

Stop it with Ctrl-C when finished. It is a temporary application, not a
persistent backend installation. For your real service, use its address and a
safe application-specific probe instead of the example bytes.

After activation, test from a **third machine** (replace VPS1's address):

```sh
python3 - <<'PYTHON'
import socket
with socket.create_connection(("198.51.100.1", 8081), timeout=3) as client:
    client.sendall(b"PING\n")
    with client.makefile("rb") as response:
        assert response.readline(16) == b"PONG\n"
print("Service exchange passed")
PYTHON
```

## Preparation and shared edits

VPS1 owns shared settings. A change creates a new immutable revision; the
running revision remains selected until a coordinated switch. VPS2 imports
shared settings rather than re-entering addresses, ports or mappings.

For one edit, on VPS1:

```sh
sudo twinlink config set transport.port 4567 --pair edge
sudo twinlink config set transport.port 4567 --pair edge --apply --yes
sudo twinlink config regenerate --pair edge --apply --yes
sudo twinlink pair export --pair edge --output /root/edge-update.p2
```

Transfer the private file to VPS2, then:

```sh
sudo chmod 600 /root/edge-update.p2
sudo twinlink pair import --pair edge --file /root/edge-update.p2 --apply --yes
sudo twinlink config regenerate --pair edge --apply --yes
```

For an established pair the stored management key authenticates the update.
First import additionally requires the independently checked export fingerprint.
Both hosts must use the same shared revision before activation.

If you made several edits before transferring, VPS2 needs each missing revision
**in order**. For example, if VPS2 has revision 2 and VPS1 has revision 4, export
3 and then 4 on VPS1 and import both in that order on VPS2:

```sh
sudo twinlink pair export --pair edge --revision 3 --output /root/edge-r3.p2
sudo twinlink pair export --pair edge --revision 4 --output /root/edge-r4.p2
```

Prepare VPS1 before exporting the final revision, then prepare VPS2 after its
final import. Preparation of initial Noise credentials can itself stage a new
revision, so inspect `pair status` for the final number.

Regeneration captures local route/NIC/gateway facts, generated configs, binary
hashes and guarded units. It cannot overwrite the active revision or run during
a transition. After a binary/local-facts change or an update requiring new unit
content, stage a new revision on VPS1 and follow the same preparation/transfer
flow. The launch guard checks selected-revision configs and binary pins on every
systemd start and automatic restart. Standby units remain disabled.

Adding/editing/deleting a service follows this same flow. Removing the last
service makes active profiles incompatible: coordinate off rather than activating
an empty configuration. Kernel mappings support up to 256 expanded ports and
matching-width or many-to-one ranges. Probe/config totals must fit revision and
bundle limits; oversize edits are rejected before state changes.

## Activation and recovery

Check the intended profile on both hosts, then begin `profile switch` on VPS1.
Neither `profile check` nor a preview changes runtime. A check is local and may
execute your configured safe backend probes on VPS2; it does not contact the peer
CLI or reconcile ownership journals.

The applied switch returns an outgoing receipt plus `next_host`, `next_step` and
`next_command`. Copy receipts privately and follow the returned commands. Replace
`RECEIPT` with the incoming file and `NEXT_RECEIPT` with a new output filename;
keep the returned transaction, revision and step. Exit 3 / `pending` is normal
between steps, including final commit acknowledgements. Never treat an early
local success as completion on both hosts.

| Phase | What happens |
| --- | --- |
| Preflight | Both hosts validate matching revisions, prepared configs/binaries, ownership and probe recipes; VPS2 checks proposed backends. |
| Quiesce | VPS1 withdraws exposure, then VPS2 stops. Both receipts are required before target startup. Existing connections end. |
| Start | Target resources start in the selected profile's dependency order. |
| Verify | Both hosts verify resources; VPS2 checks application exchanges through VPS1's published services. |
| Commit | Selection and last-good state are recorded and final acknowledgements exchanged. |

Keep clocks synchronized. Preflight/receipt evidence has a five-minute freshness
window. Each target host arms a systemd timer before exposure; the verification
budget is 60 seconds and includes manual transfer time after startup. Expiry
withdraws the local unverified target even if the CLI has exited. It does not
establish that the peer has stopped. Arrange receipt transfer before starting.

If receipt delivery is interrupted, inspect:

```sh
sudo twinlink recover --pair edge
sudo twinlink pair status --pair edge
```

Outgoing receipts are also retained privately under
`/var/lib/twinlink/journals/receipt-PAIR-TRANSACTION.json`. Retrying a completed
local step returns its receipt without repeating that mutation. For an expired
intermediate receipt, use the issuer's returned `refresh_command` with a new
output filename. Refresh revalidates the phase; it does not extend the original
preflight or verification budget.

A preflight-only transaction can be cancelled locally on **both** hosts:

```sh
sudo twinlink recover --pair edge --cancel-preflight --apply --yes
```

After disruptive steps or verification expiry, begin coordinated rollback using
the recovery instructions, for example on the indicated host:

```sh
sudo twinlink recover --pair edge --rollback \
  --output /root/edge-rollback-01.json --apply --yes
```

Continue its receipts on both hosts. Rollback withdraws target runtime on both
sides before restoring the saved revision/profile and verifying it. An unreachable
peer or ownership conflict can leave reachable hosts off pending recovery.
Preserve the private state and journals until the operation finishes.

For normal deactivation, begin on VPS1:

```sh
sudo twinlink profile switch off --pair edge \
  --output /root/edge-off-01.json --apply --yes
```

Follow every returned shutdown/acknowledgement step. `profile restart` and
`profile reapply` also coordinate both hosts and use the active revision;
`profile switch` explicitly activates staged settings.

## Diagnostics

```sh
sudo twinlink doctor --pair edge
sudo twinlink doctor --pair edge --deep
sudo twinlink doctor --pair edge --watch 5m --interval 1 \
  --export /root/edge-report.json
```

Doctor observes the active revision and shows staged settings separately.
It gathers bounded host/route/link/unit/nft evidence and configured application
exchanges. A selected or restored profile can remain `active-unverified` in
status; doctor reports evidence-based health separately.

| Verdict | Meaning |
| --- | --- |
| `off` | Pair is selected off without a pending transition. |
| `healthy` | Required local resource and sampled delivery checks passed at this vantage. |
| `degraded` / `failed` | Observed required checks failed. Read the cited evidence. |
| `unknown` | Required evidence is missing or unavailable. |

An unavailable nft comment compatibility read leaves ownership unknown when
other table/rule observations match. Timeouts or truncated evidence alone do
not justify a drift finding. Explicit marker/rule/GRE mismatches still fail.
Healthy local probes do not establish independent Internet reachability; test
from a third machine as well.

Exports are mode 0600 and need a new filename. Default `share` redaction removes
credentials and pseudonymizes addresses, ports, identities and interfaces while
preserving within-report relationships. `secrets` removes credentials but retains
diagnostic identities/ports; keep these reports private. To merge reports from
both hosts, collect each with `--redaction secrets` and transfer them privately.
On VPS1:

```sh
sudo twinlink doctor --pair edge --redaction secrets --export /root/vps1-private.json
```

On VPS2:

```sh
sudo twinlink doctor --pair edge --redaction secrets --export /root/vps2-private.json
```

Copy both private files to one host, then merge there:

```sh
sudo twinlink doctor --merge /root/vps1-private.json /root/vps2-private.json \
  --export /root/paired-share.json
```

The merged output uses share redaction by default. Independently pseudonymized
share reports cannot establish paired identity. Compare a prior private report
with `doctor --pair edge --redaction secrets --compare /root/old-private.json`.

Quick/deep collection budgets are 15/60 seconds; commands have a three-second,
64 KiB output budget. Watch supports intervals of at least 250 ms, at most one
hour, 100,000 samples and a 10 MiB final report. Sampling gaps/truncation remain
visible; unsampled probes are unknown. ICMP success alone is not delivery proof.

## Reboot and upgrade

Preparation installs an owned, enabled restore coordinator. On boot it restores
only committed selections. Off stays off; interrupted cutovers boot off pending
recovery. Each pair is handled independently so one failure does not prevent
unrelated pairs from being attempted. Restored traffic still needs delivery
verification; actual systemd/reboot acceptance remains unrun.

Install an updated checkout with the same installer and paths. Installation does
not automatically convert an older deployment's state. The explicit
`config migrate` preview inventories an offline deployment; ambiguous groupings,
credential changes and incomplete provenance require operator review. This is
not part of the new-pair walkthrough. Preserve private backups and recovery
access before changing an existing deployment.

## Removal

Complete coordinated off for every affected pair first. Deletion is local:
repeat it on each host after both sides finish shutdown.

```sh
sudo twinlink pair delete --pair edge
sudo twinlink pair delete --pair edge --apply --yes
sudo twinlink system changes
```

Pair deletion removes unchanged owned resources, configs, credentials and history,
while preserving other pairs and foreign changes. An interrupted deletion can
resume with the same command. Ownership conflicts require inspection rather
than force deletion. Shared settings are restored after their last owner is
released and only when observations match the recorded baseline/applied values.

For a full local uninstall instead of individual pair deletion:

```sh
sudo twinlink uninstall --plan
sudo twinlink uninstall --purge --apply --yes
```

Run it separately on each host after every pair completes coordinated off.
Removal verifies installation hashes, restores eligible owned settings and
checks recorded dependency changes before removing program/recovery files last.
Unknown package provenance, foreign dependents or edited files produce conflicts
and preserve recovery access. Retry interrupted cleanup after inspecting its
journal; do not erase it manually.

`sudo scripts/uninstall.sh` is program-only removal: it can retain runtime and
services needed by managed records. Use the v2 `uninstall --purge` flow above for
full local cleanup. Separately installed Rathole binaries and exported files
outside TwinLink storage remain operator-owned. Local cleanup never claims that
the peer is clean.
