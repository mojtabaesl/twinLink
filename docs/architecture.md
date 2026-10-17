# Architecture

[README](../README.md) · [Operations guide](operations.md) · [Verification](verification.md)

TwinLink 2.0.0a1 stores one shared configuration per server pair and derives four
profile manifests from it. Each pair selects one profile or off. Different pairs
can coexist when their endpoints, GRE identities, subnets and ports do not
conflict. Selection is manual; automatic failover and GRE + Paqet are excluded.

## Profiles and roles

| Profile | Path | Local resources |
| --- | --- | --- |
| `gre-kernel` | Client → VPS1 NAT → GRE → VPS2 NAT → backend | GRE, forwarding sysctl, dedicated nft rules and scoped translations |
| `gre-rathole` | Client → VPS1 Rathole → GRE → VPS2 Rathole → backend | GRE plus Noise/TCP configs and processes |
| `direct-rathole` | Client → VPS1 Rathole → public TCP → VPS2 Rathole → backend | Noise/TCP configs and processes, without GRE |
| `direct-paqet` | Client → VPS1 Paqet client → raw/KCP → VPS2 Paqet server → backend | Candidate configs and packet exceptions; activation currently gated |

Kernel supports bounded TCP/UDP ranges but cannot DNAT to VPS2 loopback. Rathole
0.5.0 accepts TCP and can reach loopback backends. The Paqet candidate is
`v1.0.0-alpha.21`; runtime qualification pins and qualified protocols remain empty.
No Paqet TCP/UDP delivery support is claimed.

The separate `paqet install` command has pinned archive/executable hashes for
Linux x86_64/ARM64. These authenticate installation without enabling runtime
qualification. Newly installed binaries enter the ownership ledger for conditional
cleanup; existing external binaries remain unowned.

A pair has one `transport.port`: Rathole connects to VPS1's public address in
direct mode or its GRE address in GRE mode; Paqet would use VPS2's raw transport
tuple. Public service ports and backend ports remain distinct from that port.
GRE uses IP protocol 47. Kernel forwarding and GRE alone do not encrypt traffic.

## Revisions and storage

VPS1 authors immutable revisions. VPS2 imports them with authenticated lineage
checks. Staging N+1 retains N's active runtime until an explicit coordinated
switch. Active, staged and last-good resources remain available for recovery;
retained canonical revisions can be exported to transfer intermediate edits.

Default storage is `/var/lib/twinlink`:

| Path | Purpose |
| --- | --- |
| `state.json` | Pair roles, staged/active selection and transition pointers |
| `revisions/PAIR/NUMBER/` | Canonical shared settings, role credentials, local facts, generated artifacts and preparation records |
| `ownership.json` | Original values, applied fingerprints, owners and restoration status |
| `baseline.json` | Installer provenance and package changes |
| `journals/` | Durable staging, coordination, receipts and recovery intent |

Private directories/files use restricted modes and reject symlink paths.
Revision/bundle aggregate byte limits are validated before staging. The bounded
ledger stores original restoration bytes and applied fingerprints instead of
duplicate generated bodies. Obsolete generated revision records are retired
without discarding active/last-good recovery data.

## Pairing and coordination

A `p2.` bundle contains shared settings, peer-required credentials and a random
management key. It excludes VPS1's Noise private key and local runtime facts.
Bootstrap requires a full SHA256 fingerprint checked through independent trust;
the embedded checksum alone is not authentication. Established updates and
receipts use HMAC with the stored management key. This authenticates key holders,
not independently attested machines.

The coordinator advances journaled local steps with manually transferred receipts:
preflight → VPS1 quiesce → VPS2 quiesce → ordered start → verification → commit
and final acknowledgements. Receipts bind pair, revision/digest, roles, operation,
epoch, transaction, phase, nonce, time and prior history. Local locks cover
mutations, not the human transfer interval. This is not an atomic two-host
transaction.

Missing verification recipes and failed VPS2 backend exchanges block preflight.
A durable systemd timer withdraws unverified exposure after the original local
60-second verification budget. Rollback requires withdrawal barriers on both
hosts before the saved profile can return. Unknown peer state remains unknown.

## Ownership and boot

The ownership ledger captures durable before/after evidence before mutations.
Resource names alone never authorize deletion. GRE aliases, exact nft table
markers/expressions, file fingerprints and systemd fragments/drop-ins provide
additional checks. Compatibility text reads can recover nft table comments
omitted by JSON serializers; unavailable diagnostic proof remains unknown.
Unrelated firewall tables, routes, interfaces and third-party edits are preserved.

Settings shared by multiple pairs are reference-counted. Restoration requires
the last owner and a matching applied/original observation; conflicts preserve
resources and recovery records. Cleanup resumes recorded restoration after
interruptions. Program removal is authenticated and happens last.

Preparation creates disabled profile units and one enabled restore coordinator.
Every process launch/restart checks the selected revision, prepared config and
binary fingerprints. Boot attempts only committed selections, handles failures
per pair and reports active-unverified state. Interrupted transitions remain off.

## Modules

| Modules | Responsibility |
| --- | --- |
| `contracts.py`, `profiles.py`, `paqet.py` | Shared validation, capabilities and rendering |
| `store.py`, `pair_bundle.py` | Private revisions, atomic state writes and pairing trust |
| `coordination.py`, `profile_runtime.py` | Receipt barriers, local runtime and expiry withdrawal |
| `ownership.py`, `cleanup.py`, `baseline.py` | Evidence, conditional restoration and authenticated cleanup |
| `diagnostics.py`, `reports.py`, `redaction.py` | Bounded evidence, conservative findings and report privacy |
| `cli.py`, `v2_cli.py`, `menu.py` | Commands and interactive navigation |

Diagnostics are read-only and separate selection from health. Healthy verdicts
require required resource and application evidence; missing proof is unknown,
while observed mismatches can justify failure findings. Linux packet/systemd,
reboot and real external-client qualification remain release work, as recorded
in [verification](verification.md).
