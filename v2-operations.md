# V2 operations and release boundaries

This is an unqualified development release. Unit tests simulate local resources;
they do not establish actual Linux/systemd, provider, reboot, or Internet delivery.
Keep console access during qualification. Existing v1 deployments retain their
inspection/recovery/lifecycle commands until explicit migration.

## Configure once

VPS1 authors shared revisions. `setup` with no flags opens a terminal wizard;
scripted setup accepts `--pair`, `--vps1`, `--vps2`, and one `--transport-port`.
Preview commands first; repeat mutations with `--apply --yes` to execute.

```sh
twinlink setup --pair edge --vps1 198.51.100.1 --vps2 203.0.113.2 --transport-port 3456
twinlink service add web --pair edge --bind 198.51.100.1 --protocol tcp \
  --ports 8081-8082 --backend-address 10.20.30.40 --backend-ports 80-81
twinlink config show --pair edge
twinlink config regenerate --pair edge
```

No mapping is silently dropped. Kernel TCP/UDP supports bounded ranges and
many-to-one mappings but cannot DNAT to VPS2 loopback. Rathole profiles require
TCP and a prepared 0.5.0 binary with Noise. Generate initial keys through that
binary at setup/preparation. Missing tools/credentials leave profiles unavailable.
Changing local route/NIC/gateway facts requires explicit regeneration.
Different pairs reserve GRE endpoint/key identities as well as ports and
private subnets, including reversed endpoint roles and other pairs' active
revisions while newer settings are staged.

`config regenerate` prepares disabled, guarded units and records binary/config
fingerprints. It never starts a profile. Preparation cannot overwrite the active
revision. Initial Noise-key preparation can stage a new shared revision; inspect
`config show` and transfer the updated bundle. No download or key generation
occurs during switching. Existing external executables remain unowned.
Every profile, including `gre-kernel`, requires matching preparation and the
owned, persistently enabled restore coordinator before activation. Run
`config regenerate` on both hosts before the next activation after upgrading
this development release; stage a new revision first when the current revision
is active. Restoring a committed selection at boot does not arm a cutover timer.

Every process unit's launch guard revalidates the selected revision's preparation,
binary hash/path, exact generated configuration, and owned unit without writing
state or acquiring the coordinator's mutation lock. Systemd runs the same guard
on automatic restart. Missing, changed, symlinked or nonexecutable binaries,
stale preparation, edited configs, and foreign unit drop-ins block launch.
The guard carries the configured state/unit/runtime/binary paths; regenerate
units after this update to record custom paths. Paqet JSON rendering now has
stable key ordering across revision persistence; regenerate older artifacts.
Its binary trust and protocol qualification gates remain unchanged.

For nft versions that omit table comments from JSON, runtime and doctor checks
recover only the expected leading table comment from successful text output
for that exact table and installation. Explicit JSON comments are never
overridden, and full chain/rule expression checks remain required. This supports
activation and interrupted-table cleanup without trusting nested rule comments
or changing ownership fingerprints when the serializer changes.
Doctor normalizes the snapshot before rule verification and report redaction,
so collection and exports retain the same ownership result. Its text fallback
shares the collection deadline, three-second command limit and 64 KiB output
limit; failed, timed-out or truncated text cannot establish ownership.
When unavailable comment proof is the only missing check, doctor reports
`owned_nft: null` and an unknown resource/verdict instead of claiming drift.
Passing service probes alone cannot make that report healthy. Observed rule,
table identity, explicit marker or GRE mismatches still produce failure findings;
the comparison never inserts a guessed ownership marker into report evidence.

Preparation records, credentials, and local facts live under each immutable
`revisions/PAIR/NUMBER/` directory. Preparing N+1 retains N's records for boot
restoration and rollback. An initial Noise identity is committed with its new
revision; an interrupted preparation reuses its private staging journal.
Staging retires generated outputs from revisions outside the active, staged,
and last-good selections. Canonical revisions, credentials, and local facts
remain available for exporting intermediate edits. Ownership checks preserve
foreign edits; the ledger retains original restoration bytes and uses file
fingerprints for read-back rather than duplicate generated file bodies.

## One bundle per revision

On VPS1, explicitly export a new private file:

```sh
twinlink pair export --pair edge --output /root/edge.p2
```

Compare the **complete bundle's SHA256** over an independently trusted channel,
check endpoints/roles, and transfer it privately. The checksum detects corruption;
it is not bootstrap authentication. On VPS2:

```sh
twinlink pair import --pair edge --file /root/edge.p2 --expected-fingerprint SHA256
twinlink config regenerate --pair edge
```

Apply both mutation previews separately. Updates to an established pair use its
stored HMAC management key and `--pair`; importing an older revision, a lineage
fork, or conflicting content is rejected. VPS1 Noise private keys never enter
the bundle. Hidden paste and stdin (`--file -`) are supported; no secret argv.
If VPS1 has staged several edits since the last transfer, export and import
each missing revision in order, for example
`pair export --pair edge --revision 2 --output /root/edge-r2.p2`, followed by revision 3. Omit
`--revision` to export the latest staged settings. Imports still enforce the
immediate-parent digest and leave the active revision running.

Staging checks both the private revision's 64 KiB read limit and the complete
bundle's 64 KiB decompressed / 128 KiB encoded limits, including credentials
and envelope overhead, before writing artifacts or changing state. Individually
valid services/probes can exceed the aggregate budget; reduce their combined
size before staging the edit.

## Manual coordinated activation

```sh
twinlink profile check direct-rathole --pair edge
twinlink profile switch direct-rathole --pair edge --output /root/receipt-01.json
```

Applying one switch step returns status `pending` (exit 3), an authenticated
receipt, the next host, and its exact next command. Transfer the receipt privately
and follow those commands, supplying `--receipt-file` and a **new** `--output`
filename. Both hosts exchange preflight evidence, stop VPS1 then VPS2, exchange
quiescence barriers, start the target in dependency order, verify, and acknowledge
commit. The local lock is released between human steps. Same-host consecutive
steps are included in the signed receipt history. HMAC authenticates pair-key
holders, not independent machine identities. Preflight expires after five minutes.

Retrying an already completed local step returns its outgoing receipt without
repeating the transition. If that receipt expired, the issuer revalidates the
phase and renews its delivery evidence. Use the returned `refresh_command`, or
add `--refresh-receipt` to the local switch/restart/reapply/recovery command with
the last completed local `--step`, the transaction ID, and a new output filename.
For example, after VPS1 completed quiescence:

```sh
twinlink profile switch direct-rathole --pair edge --revision 2 \
  --transaction TRANSACTION_ID --step quiesce --refresh-receipt \
  --output /root/refreshed-quiescence.json --apply --yes
```

The original signed phase and its chain hash stay unchanged. A separate signed
refresh binds that exact receipt to a fresh time, expiry, and nonce, so a peer
that already consumed the original can retry safely. Both hosts must support
refreshed receipts. Renewal does not extend preflight's five-minute cutover
window or the target's 60-second verification budget; expired preflight requires
cancellation/restart, and expired verification requires coordinated recovery.

Verification requires an explicitly configured application exchange for each
service. Add `--probe-request-hex` and `--probe-response-hex` when adding/editing
the service. Use only application-safe requests and exact expected responses.
TCP accept, UDP send, or process-alive alone is insufficient. VPS2 probes the VPS1 published
service; this does not establish independent Internet reachability.
Preflight rejects missing exchange recipes before either working profile is
stopped. A prepared systemd timer is armed before each host starts its target;
the local 60-second budget includes the remaining manual verification steps.
Expiry withdraws the local target and records rollback/recovery requirements
even after the CLI exits. Pending verification can resume within the original
budget. The timer stops once both verification receipts are accepted,
or when the target is withdrawn; peer withdrawal still requires coordination.
VPS2 preflight executes the proposed backend exchanges before cutover, with at
most three seconds per exchange and 60 seconds overall. Every distinct backend
port/recipe is checked; identical many-to-one targets are probed once. A failed
or unknown exchange leaves the current selection running. This checks the
backend from VPS2, while activation verification checks the published path.

`profile check` never reconciles or writes ownership records. Pending ownership
requiring reconciliation returns a conflict; an applied lifecycle command can
reconcile under the mutation lock. Checks can run the configured safe probes.

Use `profile switch off` for coordinated deactivation. `restart`/`reapply` also
use the barriers and the active revision. Activate a staged revision explicitly
through `profile switch`. The boot coordinator restores only committed selections;
interrupted cutovers boot off pending recovery. A preflight-only failure leaves
the prior selection intact. Boot restoration reports `active-unverified`.
Boot restoration records failures per pair and continues with unrelated committed
selections. Failed startup attempts withdraw that pair's proven partial runtime;
the restore callback returns failure if any pair failed or requires recovery.

Withdrawal checks the selected/target processes first and stops proven active
ones before validating inactive artifacts. It continues other safe owned cleanup
after individual conflicts, then reports the unresolved resources. Foreign edits
remain intact, and incomplete withdrawal retains recovery/expiry protection.
An off request validates its replacement transaction and receipt chain before
replacing pending activation intent. Invalid requests leave the existing
transition and expiry protection intact. Valid off intent is durable before
runtime withdrawal; interrupted replacement retains either the original
activation intent or the new withdrawal intent.

```sh
twinlink recover --pair edge
twinlink recover --pair edge --rollback --output /root/rollback-01.json
```

Follow the recovery receipts on both hosts. Rollback withdraws target runtime
on both sides before restoring the saved revision/profile; it never invokes
legacy one-host snapshot rollback. `recover --cancel-preflight` cancels only
non-disruptive local preflight; cancel on both hosts before beginning again.
Receipts are retained privately under `journals/receipt-PAIR-TRANSACTION.json`
if output delivery was interrupted. Unknown peer state remains unknown.

## Shared edits and cleanup

```sh
twinlink config set transport.port 4567 --pair edge
twinlink service edit web --pair edge --backend-ports 8080-8081
twinlink service delete web --pair edge
twinlink system changes
twinlink pair delete --pair edge
twinlink system restore
twinlink uninstall --plan
twinlink uninstall --purge
```

Edits stage N+1 without stopping N. Prepare both hosts, transfer one new bundle,
then activate through the barriers. An empty services list makes every active
profile incompatible; select off. Pair deletion requires completed off and
removes only unchanged owned resources, configurations, secrets, and history.
An interrupted deletion can be resumed with the same `pair delete --pair ID`.
Pair deletion revalidates both recorded original and applied values for resources
left in `restoring`, including files awaiting unlink and units already disabled.
Retries finish the recorded restoration without repeating completed host changes
or releasing another pair's remaining ownership. Normal runtime readiness still
requires completed ownership; edits and foreign unit drop-ins block deletion.

System restoration is conditional: foreign changes become conflicts and are
preserved. Retrying `system restore` revalidates records left in `restoring`:
an original value already present completes without another host write; an
unchanged applied value resumes the recorded restoration. This also finishes
private-file restoration intent from interrupted cleanup while retaining other
configuration files. A known new boot with a sysctl at its exact recorded
original value releases that pair's reference without writing the setting.
Remaining pairs keep their references; changed values or unknown boot epochs
do not bypass ordinary ownership checks. Full local uninstall first requires
coordinated off for every pair.
Package removal requires exact recorded versions and a simulation with no foreign
removals; unknown provenance or dependents retain dependencies/recovery records
and return conflict. Pre-existing Python is retained. Program removal verifies the
installer manifest hashes and happens after managed-resource cleanup. A source
checkout without an installation manifest cannot authenticate program deletion.
Local success never claims peer cleanup. Exported files outside app storage are
operator-owned and are not removed by purge.
Catchable interruptions, including Ctrl-C after program deletion, restore
missing owned launcher/runtime files and private records before propagating the
interruption. The private uninstall checkpoint remains available for retry.

Installer provenance uses a shared 4 MiB byte limit and 65,536 entries per
collection across installer writes, setup/status reads, package restoration,
and resumable uninstall checkpoints. Large package inventories do not inherit
the 1,024-entry configuration limit. Oversized initial provenance is rejected
before bootstrap or directory creation.
Installer option/path checks and optional Rathole checksum/version validation
run before bootstrap, pending baseline records or dependency changes. Invalid
options can be corrected and retried without creating an interrupted install.
Previously recorded pending operations are preserved and still require their
package provenance to be resolved before retrying.

## Paqet settings and prerequisites

The renderer uses the supplied template settings: KCP manual mode, four
connections, `aes-128-gcm`, MTU 1350, nodelay 1, interval 10, resend 1,
wdelay/acknodelay false, congestion control enabled, and `SA` flags. It generates
service `forward` entries rather than SOCKS5. Keys, endpoints, interface, gateway
MAC, and transport port are derived/generated; example credentials/IPs are never
hardcoded. VPS1 is the Paqet client and VPS2 is its raw server.

The candidate is pinned to `v1.0.0-alpha.21`, source commit
`4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4`. Upstream documents root/raw-packet
access, route-source/NIC/gateway MAC discovery, and server NOTRACK/RST
suppression. Twinlink renders scoped nft rules at raw priority -300 and RST
suppression at -150, matching the dedicated address/port/peer. It does not
install broad ACCEPT rules or save a foreign firewall. Standard/ephemeral,
management, service, and other-pair port conflicts are rejected. Stopping the
process is necessary because pcap can observe packets before firewall filtering.

See the [pinned client example](https://github.com/hanselime/paqet/blob/v1.0.0-alpha.21/example/client.yaml.example),
[pinned server example](https://github.com/hanselime/paqet/blob/v1.0.0-alpha.21/example/server.yaml.example),
and [upstream architecture/prerequisites](https://github.com/hanselime/paqet#architecture--security-model).
Linux release binaries are documented as statically linked; source/dynamically
linked builds need the appropriate libpcap development/runtime libraries.

No trusted per-architecture binary hashes have been obtained in this environment.
`TRUSTED_BINARY_HASHES` and `QUALIFIED_PROTOCOLS` therefore remain empty.
Neither TCP nor UDP can activate until separately qualified against the exact
candidate. Never fill these from an arbitrary user's download or bypass the gate.

## Diagnostics and remaining work

`doctor --deep`, `--watch 5m --interval 1`, `--export FILE`, `--preview`,
`--redaction share|secrets`, `--merge A B`, and `--compare OLD` expose private,
bounded local evidence. Both redaction levels remove credentials; share also
pseudonymizes endpoints/ports/host fields. Independent per-report pseudonyms
cannot establish paired identity, so merge/compare require private secrets-level
reports. Reports conform to `docs/schemas/doctor-report-v1.schema.json`.
Imports validate nested containers, evidence/finding fields, role/redaction
values, aware timestamps, collection windows and link counter structures before
merge/compare consumes them. Invalid reports return structured exit-2 errors.
Merged output is capped after redaction, including the CLI JSON envelope, at
10 MiB. Trimming removes oldest evidence from the largest source collection,
prunes its finding references, and records truncation in that source and the
merged result. Source identities/times, both configuration snapshots and merge
provenance remain intact. Metadata that cannot fit even after evidence removal
is rejected before export or emission.

Opt-in TCP metadata capture requires `--capture --capture-interface NIC
--capture-peer IPV4 --capture-port PORT`, optionally `--capture-direction`.
It is bounded to 10 seconds/1000 packets, creates no pcap files, parses only
allowlisted metadata, and kills child processes on timeout or interruption.
Command cleanup terminates the owned process group even when the immediate
child has exited, so descendants cannot outlive the collector's budget.
Absence cannot prove filtering; offload, loss, and vantage limits apply.

Doctor describes the active revision and reports staged configuration separately.
Watch repeats configured TCP/UDP application exchanges, backend exchanges on VPS2,
public peer/gateway/GRE ICMP probes, route/link/address/listener state, selected-unit
state/restarts, bounded journal events, and applicable owned nft/conntrack evidence.
Application probes rotate in bounded batches when many ports are configured;
unsampled services remain unknown. The shared ICMP/application probe budget is
20 per second. Scheduling gaps, latency distributions, failure runs, and recovery
offsets are retained. Findings cite supporting/counter evidence for intermittent
failures, resource drift, process outages, and route/restart/pressure correlations.
Aggregate interface counters can suggest a one-way failure; they cannot establish
flow-level loss or filtering. ICMP alone does not prove application delivery.

Standby checks report artifact consistency and prepared binary hashes while
keeping live preflight/peer readiness unknown. Artifact checks compare exact
rendered byte sizes and contents, including large generated rules files; the
64 KiB command-output limit does not apply to these files. Both report redaction
levels and `logs` scrub transport tokens/keys, including unlabelled log messages.
Credential assignments use a linear scan, including long word-only messages, quoted values,
and JSON keys. Share redaction also follows nftables port/interface selectors,
including set/range operands and NAT ports. Port equality and range widths remain
consistent with structured mappings; packet/byte counters keep their values.
Ownership markers in aliases, rule comments and text hide installation/pair
identities and generated names containing ports. Known interface selector names remain
public in private reports so later share merges can scrub their operands;
operands with already-lost selectors in older private reports become opaque
pseudonyms. Secrets-level reports retain diagnostic identities/ports while
scrubbing credentials. Report merging retains both configurations and diagnoses
mismatches. Full protocol-specific
log classification, ranked causal analysis, and shared private redaction contexts
remain unfinished. Active health stays unknown without required delivery evidence.
Credential rotation and ambiguous/mixed-role multi-group migration still require
additional workflows. Explicit unambiguous **offline** migration inventories and
backs up v1, preserves GRE/service identities and compatible credentials, and
stages v2 off. Exact regenerated legacy units, managed rules, and Rathole secret
files enter the ownership ledger; shared files remain reference counted. Modified
artifacts block adoption. A proven empty legacy nft table is retired with a
resumable journal. Historical package/sysctl baselines remain unknown.

Linux fault-injection coverage, Paqet release hashes/linking verification, real
systemd reboot/uninstall VMs, and two VPSs plus an independent client are still
required. This implementation does **not** complete those release acceptance
criteria or the entire diagnostics portion of the implementation plan.
