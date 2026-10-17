# Verification record

## 17 October 2026: unknown ownership proof verdict follow-up

Doctor records compatibility-read availability per sample. If a failed,
timed-out, truncated or budget-exhausted read leaves only the table comment
unverified, `owned_nft` is null and profile resources are unknown. Passing
application probes do not promote the overall verdict to healthy or manufacture
a drift finding. Exact table/rule mismatches still fail independently of missing
proof, as do observed GRE mismatches. Any temporary header used to isolate the
missing check remains outside collected/exported evidence.

| Check | Result |
| --- | --- |
| Full unittest discovery | **502 tests: 490 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -q`; 21.644 seconds. |
| Compatibility/launch regressions | **29 tests** in `tests/test_nft_guard_review.py` passed. Existing failed/timeout/truncation/deadline cases now assert unknown verdicts and absence of drift findings; passing application probes are explicit. |
| New regression coverage | Three tests cover independently observed rule/GRE drift despite unavailable proof, share/secrets unknown exports with CLI exit 3 and no guessed marker, and watch samples moving from unavailable proof to verified ownership without spurious drift. |
| Observed mismatch findings | Existing explicit foreign markers, wrong-table/nested text and edited rules retain degraded verdicts with high-confidence drift findings referencing failing resource evidence. |
| Python compatibility | All **52** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Temporary zipapp built; version/doctor help passed; all **29** compatibility/launch tests passed against implementation modules imported from the archive. |
| Whitespace | `git diff --check` and added-file whitespace checks passed. |

Files changed in this pass: `twinlink/diagnostics.py`,
`tests/test_nft_guard_review.py`, `v2-operations.md`, and
`docs/verification.md`. No architecture or scope deviations.

Tests use temporary files and simulated host/application observations. The 12
skips remain ten Linux namespace tests and two sandbox-denied socket listener
subcases. Live Linux nft/systemd and real VPS acceptance remain unrun.

## 17 October 2026: doctor nft comment compatibility follow-up

Doctor now shares the runtime's exact-table/installation marker reader before
resource verification and report redaction. A verified kernel profile with
omitted JSON table comments therefore retains `owned_nft=true`; it can report
healthy when the other required resource and application checks pass. Both
share and secrets exports carry the normalized snapshot. Existing explicit
JSON comments remain authoritative, and recovering a marker does not bypass
chain/rule expression comparison.

The extra text command uses doctor's bounded collector and remaining deadline,
with at most three seconds and 64 KiB output. Failed, timed-out or truncated
reads cannot supply ownership proof; collection errors/truncation are recorded.
Diagnostics do not reconcile or write the ownership ledger.

| Check | Result |
| --- | --- |
| Full unittest discovery | **499 tests: 487 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -q`; 21.597 seconds. |
| Compatibility regressions | **26 tests** in `tests/test_nft_guard_review.py` passed, including six new doctor tests and extended activation/verification/collection/cleanup coverage. |
| Doctor collection/export | Valid omitted markers restore ownership/healthy verdict; share and secrets CLI exports match emitted reports, validate structurally, remain mode 0600, preserve alias/marker correspondence and leave saved state unchanged. |
| Rejected evidence | Explicit foreign JSON comments, wrong-table/foreign/nested text markers, edited rules, failed/timed-out/error/truncated commands. Positive remaining-budget and exhausted-deadline cases checked. |
| Python compatibility | All **52** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Temporary zipapp built; version/doctor help passed; all **26** compatibility/launch tests passed against modules imported from the archive. |
| Whitespace | `git diff --check` and added-file whitespace checks passed. |

Files changed in this pass: `twinlink/diagnostics.py`, `twinlink/host.py`,
`tests/test_nft_guard_review.py`, `v2-operations.md`, and
`docs/verification.md`. No architecture or scope deviations.

Tests use temporary resources, simulated nft/systemd observations and application
exchanges; no host networking or installed services were changed. The 12 skips
remain ten Linux namespace tests and two sandbox-denied local socket listener
subcases. Live Linux nft serializer and real VPS acceptance remain unrun.

## 17 October 2026: nft compatibility and launch guard review findings

Both findings are addressed within the existing runtime and ownership design:

- V2 table snapshots reuse the legacy nft comment compatibility reader with
  an exact table/installation marker. Activation, fingerprint comparison and
  interrupted withdrawal use the normalized snapshot. Foreign, nested-only,
  unreadable or mismatched text evidence cannot establish ownership; explicit
  JSON comments and full expression checks retain their authority.
- Every selected process launch validates revision-specific preparation,
  generated config bytes/modes/ownership, binary path/hash/executability, and
  owned unit fragments/drop-ins. The generated ExecCondition preserves custom
  paths and applies equally to automatic restarts and target-start attempts.
  Checks are read-only and do not reacquire the mutation lock, execute the
  binary or send network probes.
- A supporting Paqet fix sorts generated JSON keys. A positive launch test
  exposed different bytes before/after canonical revision persistence; stable
  rendering preserves valid preparation fingerprints. Trust/qualification gates
  remain unchanged.

| Check | Result |
| --- | --- |
| Full unittest discovery | **493 tests: 481 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -q`; 21.467 seconds. |
| New regression suite | **20 tests** in `tests/test_nft_guard_review.py`, all passed. |
| nft compatibility | Activation and cleanup with omitted JSON markers; interrupted apply recovery; stable fingerprints across serializer changes; rejection of foreign/nested/unreadable marker evidence and edited expressions. Legacy migration tests also pass. |
| Launch guard | Rathole/GRE Rathole/Paqet binary pin checks; restart and target-start retries; custom paths; edited/missing/insecure configs; stale/missing preparation; pending ownership without reconciliation; unit edits/drop-ins; selected revision while newer settings are staged; off/standby rejection; no writes, binary execution, probes or lock reacquisition. |
| Python compatibility | All **52** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Temporary zipapp built; version/help/profile-guard help passed; all **20** new tests passed using implementation modules imported from the archive. |
| Whitespace | `git diff --check` and added-file whitespace checks passed. |

Files changed in this pass: `twinlink/host.py`, `twinlink/profile_runtime.py`,
`twinlink/v2_cli.py`, `twinlink/paqet.py`, `tests/test_nft_guard_review.py`,
`v2-operations.md`, and `docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. New tests use private temporary resources and a
simulated host; no network, systemd, package or installed-program mutations
were performed. Actual Linux nft serializer variants, systemd restart/reboot
and real two-VPS acceptance remain unrun. Paqet remains unqualified. This pass
does not complete the remaining release acceptance work recorded below.

## 17 October 2026: two pair deletion/privacy review findings

Both findings are addressed within the existing architecture:

- Pair deletion opts into read-only validation of original/applied observations
  for `restoring` files and unit enablement. Unit fragment/drop-in/activity checks
  remain enforced. Runtime readiness keeps its stricter default ownership check.
  Retry skips shared references already released by the first attempt, retaining
  other pairs' files and the enabled shared restore coordinator.
- Share scrubbing recognizes nftables port/interface selectors, scalar/set/range
  operands and NAT port fields, preserving equality/range widths without treating
  packet/byte counters as ports. Ownership markers in aliases/comments/text hide
  installation/pair identities and generated names containing service ports.
  Private reports retain public interface selector names for later share merges;
  operands with lost selectors in older private reports are hidden opaquely.

| Check | Result |
| --- | --- |
| Full unittest discovery | **473 tests: 461 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| New regression coverage | **19 tests** in `tests/test_pair_privacy_review.py`. |
| Interrupted deletion | Retry before/after file unlink, including a unit file; before/after disabling a unit; no repeated disable after completed mutation; foreign edits/drop-ins rejected before further deletion; runtime checks stay strict; another pair's files/references/enabled restore coordinator survive. |
| Context scrubbing | TCP/UDP/transport-header source/destination ports; sets, ranges and NAT ports; equality with structured ports/interfaces; retained range widths/counters; alias/table-comment/structured identity correspondence; generated rule names; known-secret scrubbing at secrets level; lost-selector privacy in older reports. |
| Complete exports | Default share doctor export and CLI response from simulated active kernel resources; secrets-level collection followed by share merge/export of both originals; private mode-0600 outputs; schema validation and cross-field pseudonym equality checked. |
| Python compatibility | All **51** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Temporary zipapp built; version/pair-delete help/doctor help passed. Packaged-module tests passed for cleanup-only restoring validation, unchanged strict readiness, resumed removal and typed port/identity scrubbing. |
| Whitespace | `git diff --check` passed. |

Files changed in this pass: `twinlink/cleanup.py`, `twinlink/ownership.py`,
`twinlink/profile_runtime.py`, `twinlink/redaction.py`,
`tests/test_pair_privacy_review.py`, `v2-operations.md`, and
`docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. Deletion tests inject interruptions into private
temporary files and a simulated systemd host; complete exports use simulated
kernel/nft observations and application probes. Actual Linux/systemd/reboot
and real VPS acceptance remain unrun. Independent report pseudonyms still
cannot establish identity across unrelated share exports. This pass does not
complete the remaining release acceptance work recorded below.

## 17 October 2026: three restoration/installer review findings

All three findings are addressed within the existing architecture:

- System restoration passes `restoring` records through the ledger's existing
  conditional recovery logic. Already-original files, enablement and settings
  complete without repeated writes; still-applied resources resume restoration.
  Private-file restoration intent resumes while other configurations remain.
- Sysctl withdrawal recognizes a known boot-epoch change with the exact recorded
  original value, releases only the requested owner and performs no host write.
  Shared/pending acquisitions retain other references. Unknown/same boot epochs,
  wrong owners and foreign values remain protected. Pending sysctl cleanup
  delegates reconciliation to the same ledger release path.
- Installer argument/path/checksum/version validation precedes bootstrap,
  baseline mutation and dependency work. Optional Rathole version checks are
  bounded to three seconds; subprocess failures return controlled installer
  errors. Existing pending provenance is preserved rather than silently reset.

| Check | Result |
| --- | --- |
| Full unittest discovery | **454 tests: 442 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| New regression coverage | **29 tests** in `tests/test_restoration_review.py`. |
| Restoration retry | Interrupted deletion before/after unlink; pre-existing bytes/modes; foreign replacement preservation; unit/sysctl completion without duplicate writes; installation/private pair file recovery; retained unrelated configurations. |
| Reboot handling | Simulated kernel activation → reboot → coordinated off; original forwarding remains `0` without sysctl writes; shared owner release/reactivation; pending shared acquisition cleanup; unknown/same boot IDs, wrong owners and foreign values rejected. |
| Installer validation | Missing binary/checksum pairing, nonregular/nonexecutable/symlinked paths, checksum format/mismatch before execution, unsupported/failed/timed-out versions, invalid directory ancestry/permissions, unchanged upgrade files/baseline, corrected retry and trusted checks before baseline creation. |
| Python compatibility | All **50** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging/CLI | Temporary zipapp built; help/version/system-restore help passed. Packaged module restoration retry and reboot reset passed. Installer checksum-only options returned controlled exit 1 without bootstrap, state or program artifacts. |
| Whitespace | `git diff --check` passed. |

Files changed in this pass: `twinlink/cleanup.py`, `twinlink/ownership.py`,
`scripts/package.py`, `tests/test_restoration_review.py`, `v2-operations.md`,
and `docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. Restoration/reboot tests simulate host state; installer
tests use private temporary paths and fake dependency work. Actual Linux reboot,
systemd/package-manager and real VPS acceptance remain unrun. Existing conflict
records and pending installer journals are not automatically cleared. This pass
does not complete the release acceptance work recorded below.

## 17 October 2026: four uninstall/diagnostic review findings

All four findings are addressed within the existing architecture:

- Final program removal catches interruptions as well as ordinary exceptions,
  restores missing owned launcher/runtime/private records with original modes,
  retains its private checkpoint, and re-raises the interruption.
- Artifact readiness compares the expected rendered byte count and bounded
  bytes directly, independently of the 64 KiB command-output budget. Oversized,
  edited and insecure files still fail the check.
- Report imports validate required nested structures and field types, including
  evidence, findings, role/redaction values, finite nonnegative offsets, aware
  timestamps/window ordering, and link/statistics structures consumed by compare.
  Invalid input produces the documented structured validation error (exit 2).
- Final reports, including merged reports after redaction, fit the 10 MiB
  export and CLI-envelope budget. Truncation retains identities/times,
  configuration snapshots and merge provenance, marks affected sources and the
  merged result, and removes dangling finding references. Irreducible metadata
  is rejected before export/emission rather than producing an oversized file.

| Check | Result |
| --- | --- |
| Full unittest discovery | **425 tests: 413 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| New regression suite | **20 passed** in `tests/test_diagnostic_review.py`. |
| Uninstall | Ctrl-C after program deletion and after private-record deletion, plus SystemExit; original bytes/modes restored, checkpoint retained and retry completes removal. |
| Artifact bounds | A valid 256-port kernel mapping passes preflight and diagnostic readiness with a rules file above 64 KiB; same-size edits, size mismatches without body reads, and insecure modes remain drift. |
| Report imports | Malformed host/window/redaction structures, scalar/array types, evidence/finding fields and link statistics rejected; null-host merge and malformed compare produce structured exit 2; Z timestamps, both redaction levels and valid watch reports remain supported. |
| Merged bounds | Two individually valid reports above 5 MiB produce an export and complete CLI response below 10 MiB; provenance/windows/configuration snapshots and finding references retained; opaque log IDs remain safe; input reports unchanged; small merges unchanged; irreducible metadata fails before export. |
| Existing watch regression | The 1,200-sample fixture now supplies all documented evidence fields through the existing evidence constructor, so the regression exercises a valid schema-v1 watch report. |
| Python/schema compatibility | All **49** Python source/test/script files parse with Python 3.9 grammar; updated report schema parses as JSON. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Built a temporary zipapp; six CLI checks passed for help/version/doctor help, JSON status, structured null-host rejection and private paired export with retained provenance. |
| Whitespace | `git diff --check` passed. |

Files changed in this pass: `twinlink/cleanup.py`, `twinlink/diagnostics.py`,
`twinlink/reports.py`, `twinlink/v2_cli.py`,
`docs/schemas/doctor-report-v1.schema.json`, `tests/test_diagnostic_review.py`,
`tests/test_review_regressions.py`, `v2-operations.md`, and
`docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. Uninstall tests inject interruptions around private
temporary files; artifact/preflight tests use simulated hosts. Actual Linux
systemd/reboot/package-manager and real VPS acceptance remain unrun. This pass
does not complete the release acceptance work recorded below.

## 17 October 2026: five safety review findings

All five findings are addressed within the existing architecture:

- Off supersession validates candidate receipts/steps before persistence and
  atomically replaces the prior transition with durable withdrawal intent.
  Invalid requests and failed writes preserve expiry-driven withdrawal.
- Staging rejects oversized canonical revisions and complete pairing bundles
  before artifact retirement, journaling or state changes. The full envelope's
  credential/HMAC overhead counts toward the existing transfer bounds.
- Credential log assignments use a linear scanner instead of overlapping
  wildcard matching, with coverage for quoted/escaped values and JSON keys.
- Installer baseline writers/readers share a 4 MiB byte budget and 65,536-item
  collection budget, including setup, system status, package restoration and
  embedded uninstall recovery checkpoints. Configuration limits are unchanged.
- Bounded command cleanup terminates the owned session's process group after
  the immediate parent exits, including timeout, overflow and interruption.

| Check | Result |
| --- | --- |
| Full unittest discovery | **405 tests: 393 passed, 12 skipped**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| New regression suite | **23 passed** in `tests/test_safety_review.py`. |
| Withdrawal intent | Invalid receipts on both roles; wrong chains/steps/transaction IDs; failure before and after atomic replacement; durable off intent before runtime withdrawal; expiry actually stops the simulated target in each failure case. |
| Revision bounds | Nine maximum-probe services rejected without artifacts; a revision below 64 KiB rejected for full-bundle overhead; rejected edits preserve active state/ledger/files; a large accepted revision remains readable/exportable. |
| Redaction | 32 KiB word-only and repeated-keyword inputs complete within a four-second subprocess budget; seeded secrets, quoted/escaped assignments, JSON keys and unterminated values are scrubbed. |
| Baselines | Installer-generated 1,100-package provenance survives setup, system status, upgrade reads, pending install snapshots, dependency cleanup and interrupted/resumed program removal; excessive byte/count writes fail before bootstrap creation. |
| Descendants | Real self-created subprocess groups stop producing heartbeats after timeout, output overflow, interruption and success, even after parent exit. All four tests also detect the old cleanup logic in an in-memory regression sensitivity check. |
| Python compatibility | All **48** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Built a temporary zipapp; six CLI checks passed for help/version/profile help, JSON status/setup preview and invalid setup exit 2. Packaged-module checks passed for large baseline reads, staging/bundle round-trip, complete-bundle rejection and long-message redaction. |
| Whitespace | `git diff --check` passed. |

Files changed in this pass: `twinlink/coordination.py`, `twinlink/store.py`,
`twinlink/baseline.py`, `twinlink/redaction.py`, `twinlink/diagnostics.py`,
`twinlink/cleanup.py`, `twinlink/v2_cli.py`, `scripts/package.py`,
`tests/test_safety_review.py`, `v2-operations.md`, and `docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. Process cleanup uses real local children; resource,
package and systemd mutations use simulated hosts/private fixtures. Actual
Linux reboot/systemd/package-manager behavior and real VPS acceptance remain
unrun. This pass does not complete the remaining release acceptance work below.
The staging guard prevents new oversized revisions; it does not rewrite already
oversized or corrupt revision files, which still require explicit recovery.

## 17 October 2026: six lifecycle review findings

This pass addresses all six findings without changing the profile architecture:

- Withdrawal stops proven active processes before inspecting inactive artifacts,
  attempts remaining owned resource withdrawal despite individual conflicts, and
  reports the preserved conflicts afterward. Expiry uses the same ordering.
- VPS2 preflight executes safe application exchanges against the proposed
  backend ports, including bounded ranges, before either host cuts over. Each
  distinct target/recipe gets at most three seconds within a 60-second budget.
- Cross-pair reservations reject duplicate GRE endpoint/key identities, including
  reversed endpoint roles and conflicts with active versus staged revisions.
  This restores the existing v1 validation rule; the referenced
  [Linux tunnel creation path](https://github.com/torvalds/linux/blob/v6.1/net/ipv4/ip_tunnel.c#L1064-L1081)
  rejects an identity already found in the namespace.
- Boot records per-pair preflight/startup/withdrawal failures, continues restoring
  other committed pairs, and returns an aggregate nonzero result when needed.
- Pending phase receipts can be retrieved or renewed after local revalidation.
  A separately authenticated refresh preserves the original chain hash and
  works whether the peer has already consumed the phase or not. Replay, forgery,
  phase/epoch binding, preflight freshness, and verification expiry remain enforced.
- `profile check` uses read-only ownership access. Pending enablement or nft
  reconciliation cannot save a ledger update without an applied lifecycle step.

| Check | Result |
| --- | --- |
| Full unittest discovery | **382 tests, no failures, 12 skips**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| New regression suite | **30 tests** in `tests/test_lifecycle_review.py`. |
| Withdrawal | Active direct Rathole and kernel resources withdraw despite an edited inactive unit; expiry preserves the edited artifact and records recovery requirements. |
| Backend preflight | Actual TCP/UDP exchange code with injected sockets, wrong datagrams, unreachable/unknown targets, all range ports, many-to-one deduplication, and total/per-exchange budgets. |
| Multi-pair behavior | GRE key/endpoint conflicts in both orientations; distinct identities; active/staged reservations; isolated boot preflight/startup failure and shared-forwarding ownership; CLI aggregate failure. |
| Receipts | Expired intermediate quiescence, original-command retry, already-consumed originals, immutable chain identity, invalid/expired/replayed refresh rejection, revalidation failure, prepare/start/commit checks, recovery/final acknowledgement renewal, private CLI output, and unchanged verification expiry. |
| Ownership checks | Pending enablement/nft proofs stay byte-for-byte unchanged under `profile check`; the applied lifecycle can subsequently reconcile under its lock. |
| Python AST | All **46** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Built `/private/tmp/twinlink-lifecycle-review.pyz`; ten packaged checks passed, covering help/version, switch/recovery refresh flags, JSON status/preview, aggregate restore exit 1, retained revision export, and invalid setup exit 2. |
| Whitespace | `git diff --check` passed. |

Files changed in this pass: `twinlink/contracts.py`, `twinlink/ownership.py`,
`twinlink/profile_runtime.py`, `twinlink/coordination.py`, `twinlink/v2_cli.py`,
`twinlink/cli.py`, `tests/test_lifecycle_review.py`, `v2-operations.md`, and
`docs/verification.md`.

The 12 skips remain ten Linux namespace tests and two sandbox-denied local
socket listener subcases. New resource/systemd tests use simulated hosts and
private temporary files. Actual Linux reboot/systemd behavior and real VPS
acceptance remain unrun; Paqet qualification gates and the other documented
unfinished release work remain unchanged. Both hosts need the updated code
to exchange renewed receipts. No host network/systemd/package changes occurred.

## 17 October 2026: eight follow-up review findings

All eight reported findings are addressed in this pass:

- Ownership writes are bounded with reserved recovery capacity. File read-back
  uses fingerprints while original restoration bytes remain intact. Old inline
  ledgers up to 64 MiB can be read and compacted. Obsolete generated revision
  artifacts retire conditionally; active, staged, and last-good outputs remain.
- `pair export --revision N` exposes retained revisions for ordered transfer of
  several staged edits, preserving immediate-parent validation and active runtime.
- Preflight rejects missing application exchange recipes before cutover and
  requires prepared, owned, persistently enabled boot restoration for kernel
  profiles as well as process profiles.
- Prepared systemd expiry units arm before target exposure and withdraw an
  unverified target after the original local 60-second budget, independently of
  the CLI. Same-boot monotonic evidence prevents wall-clock rollback extending
  the budget. Withdrawal failures retain recovery intent and retry through
  systemd. Late verification cannot issue success receipts.
- Merged reports receive the requested redaction with one export context;
  report imports accept evidence collections up to 100,000 entries within
  10 MiB without relaxing configuration/bundle parsing limits.
- Activation verification compares a complete UDP datagram exactly and rejects
  oversized expected prefixes and separate datagrams that concatenate to match.

| Check | Result |
| --- | --- |
| Full unittest discovery | **352 tests, no failures, 12 skips**, using `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q`. |
| Added coverage | 26 tests in `tests/test_review_regressions.py`, plus timer-unit validation in `tests/test_host.py`. The existing interrupted-boot fixture now prepares its coordinator explicitly. |
| Ledger recovery | A valid 256-port pair reaches revision 13, retains active/last-good artifacts, completes off barriers, and deletes successfully. Capacity refusal, reserved off-receipt space, legacy oversized compaction, foreign edits, and interrupted retirement are covered. |
| Lifecycle | Missing/stale/disabled/runtime-only boot preparation, missing recipes on both roles, timer preparation/arming order, arm failure, abandoned verification, deadline/clock rollback, in-budget resume, late success, expiry CLI callback, withdrawal failure/retry, recovery/off superseding an unverified transition, and verified-target preservation. |
| Reports and UDP | Actual merge exports at both redaction levels; merge/compare of 1,200-probe reports over 1 MiB; strict parser bounds; exact, oversized, and split UDP response fixtures. |
| Python AST | All **45** Python source/test/script files parse with Python 3.9 grammar. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Built `/private/tmp/twinlink-followup-review.pyz`; packaged help/version, retained-revision export/help, invalid-revision exit code, status JSON, watch preview, and expiry callback/help passed. |
| Whitespace | `git diff --check` passed. |

The 12 skips remain 10 Linux namespace tests and 2 sandbox-denied local socket
listener subcases. New timer behavior is tested with a simulated systemd host;
actual Linux timer scheduling, reboot, and real two-VPS/third-client acceptance
remain unrun here. No host network, package, systemd, or installed-program
changes were performed. Paqet qualification gates and the other unfinished
release work described below remain unchanged. This pass preserves the planned
architecture and uses retained exports rather than adding bundle lineage fields.

## 17 October 2026: review regression fixes

The review fixes cover revision-scoped preparation/facts/credentials, active
restart/reapply, transactional initial Noise provisioning, pending ownership
reconciliation, transport-secret redaction, repeated traffic-path diagnostics,
active/staged report separation, proven legacy-artifact adoption/cleanup, and
revision-mismatch report merging. Paqet qualification (review finding 10) remains
open: trusted per-architecture hashes and successful Linux TCP/UDP packet
evidence are not available from this development host; the safety gate remains.

| Check | Result |
| --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q` | **325 tests, no failures, 12 skips**. |
| New regression suite | 29 test methods, including before/after mutation faults, reboot/rollback with N+1 staged, boot retry after partial GRE creation, setup without native binary followed by Noise provisioning, actual logs/doctor export redaction, intermittent/one-way/pressure watch fixtures, probe rate/size bounds, mismatch merging, and migration through deletion/uninstall. |
| Skips | 10 Linux namespace tests (Darwin/no namespace runtime); 2 TCP/UDP listener subcases (sandbox denies local socket binding). Socket exchange framing/mismatch behavior also has deterministic mock coverage. |
| Python AST | All 44 source/test/script files parsed. |
| Shell syntax | `sh -n scripts/install.sh scripts/uninstall.sh` passed. |
| Packaging | Built `/private/tmp/twinlink-review-regressions.pyz`; packaged help, setup/doctor JSON previews using a temporary state path, and unit packaging checks passed. |
| Whitespace | `git diff --check` passed. |

Faults and path changes above use simulated resources; they do not establish
Linux kernel behavior or delivery between real VPSs. No host network, package,
systemd, or installed-program changes were performed.

Files affected by this review pass:

- Revision/lifecycle: `twinlink/store.py`, `twinlink/profile_runtime.py`, `twinlink/ownership.py`, `twinlink/cleanup.py`.
- Commands/diagnostics/migration: `twinlink/v2_cli.py`, `twinlink/diagnostics.py`, `twinlink/redaction.py`, `twinlink/reports.py`, `twinlink/migration.py`.
- Tests: `tests/test_v2_regressions.py`, `tests/test_profile_runtime.py`, `tests/test_v2.py`.
- Documentation: `v2-operations.md`, `docs/verification.md`.

## 17 October 2026: v2 development implementation

Executed on the development Mac. No host network, systemd, package-manager,
VPS, or installed-program mutation was performed. Tests use private temporary
directories and simulated resources; subprocess-limit tests run disposable
Python children.

| Check | Result |
| --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q` | **296 collected: 286 passed, 10 skipped**, 5.145 seconds. |
| Added v2 tests | Contracts/capabilities, template defaults/roles, shared port derivation, revision lineage/active retention, bundle trust/bounds, receipt barriers/replay/expiry, coordinated recovery, ownership/refcounts/foreign changes, reboot epochs, resumable deletion, authenticated program cleanup, report redaction/schema shape, command time/output bounds, scoped metadata capture, versioned CLI apply/output. |
| Installer baseline test | Baseline precedes program directories; modes and preservation verified. |
| Python AST parsing | All **43** Python source files parsed; no trailing whitespace. |
| Doctor schema | Valid JSON; report fields checked against the declared required schema fields. A full external JSON Schema validator was not run. |
| `sh -n scripts/install.sh scripts/uninstall.sh` | Passed. |
| Packaged zipapp | Build, help/version, non-mutating setup preview, v2 status, invalid-port exit 2, Paqet qualification refusal exit 2, doctor preview passed. |
| `git diff --check` | Passed. |

The 10 Linux integration tests were skipped because Linux/root namespace
execution is unavailable and integration opt-in was absent. The two added tests
cover direct Rathole with GRE down and candidate Paqet TCP/UDP packet paths.
The Paqet test additionally requires an independently trusted binary checksum.
No Paqet qualification or trusted per-architecture hash is claimed.

Remaining work is listed in [v2 release boundaries](../v2-operations.md#diagnostics-and-remaining-work).
In particular, advanced continuous diagnostics/cause analysis, private shared
redaction contexts, credential rotation, broader migration-choice workflows,
full transition/fault-boundary Linux coverage, systemd/reboot/uninstall VMs,
and real two-VPS/third-client acceptance are incomplete. This is not evidence
that the entire implementation plan or release acceptance suite is complete.

## Legacy verification history

Verified on 16 October 2026 on the development Mac (Darwin arm64), with Python 3.9. No live Linux network or systemd mutation was performed. No VPS installation or real Rathole handshake was performed during this update.

## Completed implementation milestones

1. Validated tunnel and forwarding records, GRE pairing, private forwarding transfer, and version/revision checks.
2. GRE lifecycle, actual kernel inspection, reachability health, drift detection, diagnostics, and systemd persistence.
3. Rathole 0.5.0 installation, shared Noise configs/processes, native key generation, named connection-port setup, legacy consolidation, base64 pairing and service management; nftables TCP/UDP forwarding, relay ranges, return NAT, and scoped conntrack cleanup.
4. Preview/apply/read-back/commit transactions, ownership protection, locks, durable rollback and interrupted-transaction recovery.
5. Two main menu workflows for GRE tunnels and Forwarding, shared Kernel/Rathole setup and pairing under `forward`, scriptable JSON CLI, executable archive, distribution installer/uninstaller, operator documentation, and Linux integration suite/CI.

## Checks actually run

| Check | Result |
| --- | --- |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -q` | 224 collected: **216 passed, 8 skipped**. |
| Linux namespace tests collected by the full suite | All 8 skipped: Linux/root networking environment unavailable; integration opt-in absent. |
| `sh -n scripts/install.sh scripts/uninstall.sh` | Passed. |
| Python AST parsing | All 26 Python source files parsed. Unit tests import all implementation modules. |
| `python3 scripts/package.py install --build-only dist/twinlink.pyz` | Built the executable archive. |
| Packaged runtime smoke | Help and the direct Forwarding menu passed. Both Kernel and shared Rathole add previews passed with temporary paths and a fixture native key generator: correct forwarding modes, grouped Rathole services, redacted credentials, no pairing code before apply, and unchanged saved state. Packaging tests cover success/error exit codes. |
| `git diff --check` | Passed. |

The unit suite uses a stateful simulated kernel for transaction tests. It checks failures, read-back mismatches, partial rollback, journal recovery, ownership refusals, real versus desired state, peer verification gates, listener conflicts, secondary binds, private-subnet route protection, secret redaction, revision edits, cascade deletion, and rathole's initial pending-peer state. It does not establish packet delivery.

New tests cover several forwarding ports in one Noise pairing code, matching tokens/public keys, private-key exclusion from codes/client state/previews, preserving the server identity during reverse imports, legacy TCP compatibility, malformed/corrupt/duplicate/unverified-peer rejection, batch failure without partial commit, import enablement/boot intent, wizard install/cancel/error handling, config paths without editor invocation, mocked official-release installation/reuse, checksum/archive/version/download failures and symlink refusal. Download and native key generation tests use mocked responses; they do not verify a real download or handshake.

Saved-state setup tests additionally cover automatic role/single-tunnel selection, numbered choices for multiple tunnels and known public/private/backend addresses, custom backend entry, reuse/export of existing forwarding, bounded generated service names, explicit Rathole name/connection-port prompts, client pairing without a tunnel selector, mixed-role selection, custom state paths, unavailable-tunnel repair guidance, invalid state, and a complete setup apply using a real private state file with the simulated kernel.

Shared-process tests cover one config/unit/port/token/keypair for multiple services, independent stop/delete with sibling listeners preserved, one restart per group, boot restoration omitting disabled services, rollback after restart failure, consolidation removing obsolete configs/units, atomic peer group import and connection-port updates, whole-group export and shared-setting/port conflict rejection. Existing per-entry configurations remain compatible until explicitly consolidated.

Unified-forwarding checks cover the two-task main menu, both setup methods under Forwarding, saved GRE reuse for Kernel UDP/ranges, Kernel pairing without Rathole installation or method selection on VPS2, shared config/editor paths, invalid-code errors, `forward add --mode rathole --ports` preview/apply, common pairing export/import with peer enablement, private-key exclusion, conflicting batch-option rejection and compatibility of existing Rathole commands.

## Linux checks supplied but not executed here

The namespace suite builds an isolated external-client → VPS1 → GRE → VPS2 → backend topology and sends real request/response payloads. Eight tests cover kernel TCP, kernel UDP, lifecycle edits/disable/delete, drift/reapply, restored enabled state, injected apply failure with working-path rollback, keyed/unkeyed GRE changes, rathole TCP/Noise process restart/restoration, and two forwarding ports sharing one Noise config/process with independent service stop. It checks preservation of unrelated firewall rules and default routes. Rathole processes are controlled by the test because namespaces do not run systemd.

Run on a disposable Linux machine with GRE, iproute2, nftables, conntrack, ping, and a trusted rathole 0.5.0 executable:

```sh
sudo env TWINLINK_INTEGRATION=1 \
  TWINLINK_RATHOLE_BINARY=/absolute/path/to/rathole \
  PYTHONPATH="$PWD" python3 -m unittest tests.integration.test_netns -v
```

The GitHub Actions workflow builds the pinned upstream rathole release with server, client and Noise features and runs this suite. No remote CI run was dispatched or observed during this task.

## Real two-server checks still required

Verify provider protocol-47 support, existing host firewall compatibility, real path MTU, both endpoints after an actual reboot, systemd stop/start/restart behavior, peer transfer/edit synchronization, and external TCP/UDP payload delivery. Confirm disabled/deleted public tuples close, including established connections. Test loss of a server, missing backend service, drift, interrupted apply/recovery, and rollback using console access. Unit tests, a committed local configuration, or an active service alone do not prove end-to-end health.

Rathole UDP is intentionally rejected until a selected version passes an end-to-end UDP suite. Kernel UDP is implemented and included in the unrun Linux namespace tests.
