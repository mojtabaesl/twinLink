# Paqet qualification evidence

[Verification](verification.md) · [Operations](operations.md)

Status on **18 October 2026**: native Linux, disposable systemd VM and real
two-host evidence are **pending**. TCP and UDP are supported mapping types in
the pinned source, but neither architecture/protocol is approved for activation.
No portable fixture or successful installation changes that policy.

## Release identity and parser audit

Release: `v1.0.0-alpha.21`, commit
`4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4`.
`twinlink/paqet_release.py` contains the reviewed archive/executable identities
for Linux amd64 and arm64. Installation and explicit preparation use those
same identities, normalizing x86_64/amd64 and aarch64/arm64 aliases. The
protocol evidence matrix remains empty. A future approved record must match
the executable SHA256, renderer version, protocol and transport-settings digest;
qualification is never read from pairing or service options.

The exact pinned [configuration loader](https://github.com/hanselime/paqet/blob/4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4/internal/conf/conf.go),
[forward parser](https://github.com/hanselime/paqet/blob/4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4/internal/conf/forward.go)
and [forward dispatcher](https://github.com/hanselime/paqet/blob/4b81ce0ab56b7cc9aec7501c87c4804676cdb1b4/internal/forward/forward.go)
were inspected. JSON-as-YAML must still pass the actual native loader in the
tests below; a Python JSON parse is not native qualification.

The [client example](https://github.com/hanselime/paqet/blob/v1.0.0-alpha.21/example/client.yaml.example)
supports forwarding without SOCKS. The [server example](https://github.com/hanselime/paqet/blob/v1.0.0-alpha.21/example/server.yaml.example)
and [security model](https://github.com/hanselime/paqet/blob/v1.0.0-alpha.21/README.md#architecture--security-model)
describe capture before ordinary firewall processing. Withdrawal therefore stops
the owned process before removing its packet exceptions. Existing server rules
are scoped to peer/local addresses and the dedicated transport port. No broad
ACCEPT/NOTRACK rule or guessed client-ephemeral exception is introduced.

## Reproduce native candidate evidence

Use a disposable Linux root host with GRE, iproute2 (including tc), nftables,
conntrack and network namespaces. Never run this on the development Mac or a
production VPS. The script creates isolated namespaces; it does not run systemd.

```sh
python3 scripts/qualify_paqet.py --binary /tmp/twinlink-paqet --fetch-only
sudo env TWINLINK_INTEGRATION=1 PYTHONDONTWRITEBYTECODE=1 \
  python3 scripts/qualify_paqet.py --binary /tmp/twinlink-paqet \
  --output /tmp/paqet-evidence.json
```

Fetch verifies both archive and executable hashes before executing the version
command. The native runner refuses a different architecture's binary. It sets
`TWINLINK_PAQET_BINARY` and `TWINLINK_PAQET_SHA256`, requires all selected tests
to execute without skips, and records architecture, SHA256, kernel/tools,
renderer/settings, failures and skipped tests. Output files are never overwritten.
CI runs this separately on amd64 and arm64 and uploads evidence; no CI result was
collected in the current Mac session.

The candidate suite covers standalone TCP/UDP with real pinned processes,
mismatched keys, one-way underlay loss and UDP reassembly at the selected KCP MTU.
The bad-key test first requires the live client PID to own its TCP/UDP listener,
then repeats negative exchanges while checking both processes remain alive.
It restores the original correct-key configuration and re-proves exact delivery
before counting the negative result. A missing or crashed client is a test failure.
It also runs the v2 coordinator/runtime with actual processes, prepared guards,
packet ownership, mixed TCP/UDP on identical numeric public ports, ranges,
many-to-one targets, both backend intents, GRE-down operation and coordinated
off. A harness-only capability override permits collecting candidate evidence
before approval; it does not change the release manifest. Systemd job scheduling
and timers are explicitly emulated in these namespace tests.

GRE host-local tests check independent TCP/UDP client exchanges, relay/backend
port translation, INPUT/reply counters, foreign INPUT/OUTPUT DROP behavior,
loopback-only rejection without standby GRE and off cleanup. Existing remote
backend namespace tests retain forwarding/masquerade coverage.

## Host prerequisites and remaining acceptance

- Route source, NIC and neighbor MAC must be real and current on both hosts.
  Explicit preparation verifies the native version and executable identity;
  launch/restart guards recheck binary/config identities and Paqet route facts.
- The server source must equal its public endpoint, and its dedicated transport
  port must be outside its ephemeral range. Server-side NAT is unsupported.
  Client NAT/provider behavior and the automatic client source port need real
  two-host qualification; namespace success alone cannot qualify that topology.
- Official Linux artifacts are static; alternate/dynamically linked builds are
  not accepted merely because their version string matches. Capture/injection
  privileges and provider raw-packet permissions remain host-specific evidence.
- Native ping is bounded and available in deep diagnostics only with verified
  preparation. The pinned ping command sends one packet without waiting for a
  reply: it is recorded as unknown delivery, never application success.
- Disposable systemd VM acceptance must cover initial start, automatic restart,
  stale NIC/MAC/config/binary rejection, original 60-second verification expiry,
  rollback, reboot, interruption, off/uninstall and foreign-policy preservation.
- Two VPSs plus an independent client must prove each protocol, MTU limits,
  packet/reset behavior in both directions, loss/recovery and cleanup. Review
  narrow client exceptions only if that evidence demonstrates a need; do not
  suppress resets across an ephemeral range.

Only after reviewing these results should a release-policy change approve an
architecture/protocol/settings combination. Untested settings, protocols,
architectures and topologies remain unqualified or explicitly experimental.
