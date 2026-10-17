# Verification and release status

[README](../README.md) · [Operations guide](operations.md)

TwinLink **2.0.0a1** is a development release. The checks below were run on the
development Mac on **17 October 2026**. Simulated host tests do not establish
Linux networking, systemd behavior or real VPS delivery.

## Checks completed

| Check | Latest result |
| --- | --- |
| Full suite: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -q` | **522 tests: 510 passed, 12 skipped**, 21.940 seconds. |
| Paqet installer: `tests.test_paqet_install` | **20 passed**, also against implementation modules imported from a built zipapp. |
| Compatibility/launch suite: `tests.test_nft_guard_review` | **29 passed** in the full suite. |
| Python 3.9 grammar | All **53** Python source/test/script files parsed. |
| Shell syntax | Installer and uninstaller scripts passed `sh -n`. |
| Packaging | Portable zipapp built; version, Paqet install help and read-only preview passed. |
| Whitespace | `git diff --check` and added-file checks passed. |

## Documentation checks

The rewritten guides replace the earlier tunnel/forwarding walkthroughs with
the pair/profile workflow. All **29** local links/anchors, **51** fenced CLI
examples, **30** shell blocks and **2** embedded Python examples were checked
for valid targets, CLI arguments or syntax as applicable.

The README's setup, service add, preparation, export/import and local profile
checks were also executed against temporary stores and simulated hosts, followed
by the VPS1 and VPS2 preflight receipt steps. Runtime remained off. Native
key generation, discovery and backend probes were injected test fixtures;
no download, real backend connection or service activation was performed.

## Paqet installer checks

`paqet install` follows the existing preview/apply command pattern and is
available before or after pair setup. It installs the pinned alpha.21 Linux
x86_64/ARM64 executable without changing runtime qualification or selecting a
profile. Archive digests were checked against the
[upstream release](https://github.com/hanselime/paqet/releases/tag/v1.0.0-alpha.21)
metadata; both official archives were fetched, matched, and inspected to compute
the executable pins. The pinned version command/build flags were checked in
upstream source. Downloaded native binaries were not executed on this Mac.

The 20 new tests cover architecture aliases, read-only preview, archive/binary
checksums, unsafe archive members, size/count limits, redirect/download/version
failures, foreign files/symlinks/permissions, publication races, interrupted
install retry, large-binary fingerprints, conditional restoration, interrupted
unlink, fresh/existing-pair CLI dispatch and complete local uninstall. Downloads
and native execution in these tests are injected fixtures. New binary ownership
uses bounded hashes rather than embedding executable bodies in the ledger.

Files changed for this installer: `twinlink/paqet.py`, `twinlink/cli.py`,
`twinlink/ownership.py`, `twinlink/cleanup.py`, `tests/test_paqet_install.py`,
`README.md`, `docs/commands.md`, `docs/operations.md`, `docs/architecture.md`,
and this record. The command uses the existing ownership/restoration mechanism;
Paqet runtime qualification gates are unchanged.

The 12 skips are ten Linux namespace integration tests and two sandbox-denied
local socket listener subcases. No host networking, systemd, package-manager or
installed-program mutation was performed. Upstream metadata/archive fetching
was read-only; actual Linux native installation and two-VPS packet qualification
remain unrun.

Coverage includes shared configuration and profile compatibility; revision and
bundle limits/lineage; authenticated receipt barriers, refresh and expiry;
preflight/backend probes; ownership/refcounts and reboot epochs; interrupted
cleanup and uninstall recovery; binary/config launch pins; nft JSON-comment
compatibility; bounded diagnostics, unknown-versus-drift verdicts, redaction,
report validation and export limits. Positive packet exchanges in simulated
hosts do not replace real application-delivery tests.

## Acceptance work remaining

- Run namespace TCP/UDP packet tests on disposable Linux, including GRE, owned
  nft rules, connection withdrawal and unrelated-resource preservation.
- Qualify actual systemd start/restart, verification expiry, reboot restoration,
  interrupted transitions and uninstall on disposable VMs.
- Test two real VPSs plus an independent client for provider/firewall behavior,
  MTU, public delivery, service failure and recovery.
- Complete Paqet runtime binary qualification and qualify TCP and UDP separately
  against the pinned candidate before enabling either protocol. Installer pins
  alone do not establish runtime packet compatibility.
- Finish broader fault-injection coverage, credential rotation, ambiguous
  migration workflows and advanced diagnostic cause analysis/private shared
  redaction contexts.

The test count is not a claim that the complete implementation plan or release
acceptance criteria have been satisfied.
