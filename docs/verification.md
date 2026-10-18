# Verification and release status

[README](../README.md) · [Operations guide](operations.md) · [Paqet evidence](paqet-qualification.md)

TwinLink **2.0.0a1** remains a development release. Portable checks were run on
the development Mac on **18 October 2026**. Simulated host results do not prove
Linux networking, systemd behavior or real VPS delivery.

## Completed portable checks

| Check | Result |
| --- | --- |
| Full suite | **557 tests: 542 passed, 15 skipped**, 24.299 seconds. |
| Backend/installer tests from a built zipapp | **42 passed**; both new implementation modules loaded from the archive. |
| Python 3.9 grammar | All 58 application/test/script files parsed. |
| Packaging/help | Zipapp build, version, service add `--backend-local`, and qualification-runner help passed. |
| Shell and whitespace | Install/uninstall shell syntax and `git diff --check` passed. |
| Documentation | **37** local links/anchors, **35** shell blocks and **54** CLI examples passed. |

Focused coverage includes omitted/explicit/reset/edit-preserved backend intent,
menu defaults, schema-2 unchanged canonical bytes and bundle digest, schema-3
round trips, old explicit loopback semantics, parent lineage and stable
credentials. Rendering tests cover GRE/private-address edits, local INPUT/reply
rules and original relay-port matching, TCP/UDP/ranges, absence of local
masquerade, and preserved explicit remote forwarding.

Runtime fixtures cover deferred wildcard-binding evidence without standby GRE,
loopback-only rejection, exact-target checks before public exposure, connected
and selected return routes, saved preliminary readiness, binary/config launch
pins, and Paqet process verification even when packet rules match. Doctor uses
the same protocol-aware exchange helper, resolves backend intent consistently,
checks Paqet route/neighbor/rule evidence, records counter deltas, and preserves
unknown proof. New conntrack port selectors are scrubbed in share reports.
The overlapping local backend range regression allows public `8081-8082` to
backend `10001-10002`, still rejecting undeclared relay listeners and failed
application exchanges. Portable harness fixtures ensure delayed, missing,
foreign-owned or crashed client listeners cannot count as bad-key evidence.

The portable suite retains ownership/recovery/expiry, nft comment compatibility,
report bounds/redaction, installer and uninstall interruption regressions.
Positive simulated probes and injected qualification records are unit fixtures;
they never update or qualify the shipped release manifest.

## Native candidate harness and CI

The Linux workflow now has separate amd64/arm64 Paqet candidate jobs. Each fetches
and verifies the exact reviewed release, sets the native binary/hash environment,
requires every selected test to run without skips, and uploads kernel/tool,
architecture/hash, renderer/settings and result metadata. These new jobs have
**not been executed in this Mac session**.

New namespace tests exercise GRE host-local TCP/UDP using an independent client,
relay/backend port translation, INPUT/reply counters, foreign INPUT/OUTPUT DROP,
loopback-only rejection without standby GRE and off cleanup. Existing separate
backend-namespace tests retain remote forwarding/masquerade coverage.

The Paqet candidate tests use actual processes to exercise parser/configs,
standalone TCP/UDP, mismatched keys, one-way loss, selected-MTU reassembly,
mixed protocols sharing numeric ports, ranges/many-to-one, both backend intents,
GRE-down operation and v2 coordination/off. Process start/stop and systemd job
state are emulated inside namespaces; these are not real systemd timer/reboot
results. See the exact commands and acceptance checklist in
[Paqet qualification](paqet-qualification.md).

## Files changed for this follow-up

Paths below are repository-relative; application modules are under `twinlink/`.

| Area | Files |
| --- | --- |
| Backend contract and rendering | `backends.py`, `contracts.py`, `profiles.py`, `render.py`, `host.py` |
| Interface and lifecycle | `v2_cli.py`, `menu.py`, `profile_runtime.py`, `coordination.py` |
| Paqet identity and diagnostics | `paqet.py`, `paqet_release.py`, `diagnostics.py`, `redaction.py` |
| Native harness and CI | `scripts/qualify_paqet.py`, `.github/workflows/linux-integration.yml`, `tests/integration/test_netns.py` |
| Portable tests and schema fixtures | `tests/test_backends.py`, `tests/test_native_qualification.py`, `tests/test_nft_guard_review.py`, `tests/test_paqet_install.py`, `tests/test_profile_runtime.py`, `tests/test_review_regressions.py`, `tests/test_safety_review.py` |
| Documentation | `README.md`, `docs/commands.md`, `docs/architecture.md`, `docs/operations.md`, `docs/verification.md`, `docs/paqet-qualification.md`, `v2-operations.md` |

Earlier uncommitted Paqet output changes in `cli.py`, `presentation.py` and
their documentation/tests were preserved. The existing store, bundle and migration
paths already delegate nested revision validation to the shared contract; their
schema-2/3 behavior is exercised without changing the host-state/envelope format.

## Evidence still pending

- Execute the new native namespace tests on disposable Linux for each architecture.
- Run disposable systemd VM acceptance: initial start and restart, stale facts,
  original verification expiry, rollback, reboot, interruption and uninstall.
- Test two real VPSs with an independent client for public service delivery,
  provider/firewall/capture permissions, reset behavior in both directions,
  NAT assumptions, MTU limits, application failure and cleanup.
- Review evidence separately for each Paqet architecture/protocol/settings/mapping
  combination before approving it. The release manifest currently has **no
  approved TCP or UDP combinations**. Both installer and preparation recognize
  the reviewed executable identity; neither fact qualifies packet behavior.

No Linux network, firewall, systemd or package changes were made on the Mac.
The skips are **13** Linux namespace cases and **2** sandbox-denied local socket
listener subcases. Native CI, systemd VM and two-VPS checks remain unrun here.
Upstream pinned source was read to audit the parser, protocol dispatcher,
network/transport settings and ping command. Earlier installer archive identity
checks remain valid; no Linux native executable was run here. Pending evidence
is not represented as passed and Paqet activation remains gated.
