# Verification record

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
