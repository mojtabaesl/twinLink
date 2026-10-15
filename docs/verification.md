# Verification record

Verified on 15 October 2026 on the development Mac (Darwin arm64), with Python 3.9. No live Linux network or systemd mutation was performed. The Tunnel-Panel reference checkout was read only and has no working-tree changes.

## Completed implementation milestones

1. Validated tunnel and forwarding records, GRE pairing, private forwarding transfer, and version/revision checks.
2. GRE lifecycle, actual kernel inspection, reachability health, drift detection, diagnostics, and systemd persistence.
3. Rathole 0.5.0 TCP configuration and service management; nftables TCP/UDP forwarding, relay ranges, return NAT, and scoped conntrack cleanup.
4. Preview/apply/read-back/commit transactions, ownership protection, locks, durable rollback and interrupted-transaction recovery.
5. Guided menu, scriptable JSON CLI, executable archive, distribution installer/uninstaller, operator documentation, and Linux integration suite/CI.

## Checks actually run

| Check | Result |
| --- | --- |
| `python3 -m unittest discover -s tests -q` | 158 collected: **152 passed, 6 skipped**. |
| `python3 -m unittest tests.integration.test_netns -v` | All 6 skipped: Linux/root networking environment unavailable; integration opt-in absent. |
| `sh -n scripts/install.sh scripts/uninstall.sh` | Passed. |
| Python AST parsing | All 22 Python source files parsed. Unit tests import all implementation modules. |
| `python3 scripts/package.py install --build-only dist/twinlink.pyz` | Built the executable archive. |
| Packaged runtime smoke | Help, version, success/error exit codes, valid JSON plan, verification/rollback preview, and no state writes during preview passed. |

The unit suite uses a stateful simulated kernel for transaction tests. It checks failures, read-back mismatches, partial rollback, journal recovery, ownership refusals, real versus desired state, peer verification gates, listener conflicts, secondary binds, private-subnet route protection, secret redaction, revision edits, cascade deletion, and rathole's initial pending-peer state. It does not establish packet delivery.

## Linux checks supplied but not executed here

The namespace suite builds an isolated external-client → VPS1 → GRE → VPS2 → backend topology and sends real request/response payloads. Six tests cover kernel TCP, kernel UDP, lifecycle edits/disable/delete, drift/reapply, restored enabled state, injected apply failure with working-path rollback, keyed/unkeyed GRE changes, and rathole TCP process restart/restoration. It checks preservation of unrelated firewall rules and default routes. Rathole processes are controlled by the test because namespaces do not run systemd.

Run on a disposable Linux machine with GRE, iproute2, nftables, conntrack, ping, and a trusted rathole 0.5.0 executable:

```sh
sudo env TWINLINK_INTEGRATION=1 \
  TWINLINK_RATHOLE_BINARY=/absolute/path/to/rathole \
  PYTHONPATH="$PWD" python3 -m unittest tests.integration.test_netns -v
```

The GitHub Actions workflow builds the pinned upstream rathole release and runs this suite. No remote CI run was dispatched or observed during this task.

## Real two-server checks still required

Verify provider protocol-47 support, existing host firewall compatibility, real path MTU, both endpoints after an actual reboot, systemd stop/start/restart behavior, peer transfer/edit synchronization, and external TCP/UDP payload delivery. Confirm disabled/deleted public tuples close, including established connections. Test loss of a server, missing backend service, drift, interrupted apply/recovery, and rollback using console access. Unit tests, a committed local configuration, or an active service alone do not prove end-to-end health.

Rathole UDP is intentionally rejected until a selected version passes an end-to-end UDP suite. Kernel UDP is implemented and included in the unrun Linux namespace tests.
