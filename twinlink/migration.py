"""Explicit offline v1 migration inventory; reads never migrate installations."""
import copy

from .contracts import new_revision
from .models import ValidationError
from .rathole_groups import group_name


def inventory(store, runtime, state):
    """Prove ownership from exact v1 regeneration before changing anything."""
    from .render import render_files, render_nft, tunnel_unit_name, rathole_unit_name, rathole_config_path
    from .ownership import Ownership
    from .profile_runtime import nft_matches
    from .store import StateError
    from .contracts import digest
    from .engine import _canonical_nft
    ledger = Ownership(store)
    expected = render_files(state, str(store.directory), str(runtime.unit_dir), runtime.executable, runtime.binaries["rathole"])
    owners = {path: set(state["tunnels"]) for path in expected}
    for name in state["tunnels"]:
        owners[str(runtime.unit_dir / tunnel_unit_name(name))] = {name}
    for entry in state["forwards"].values():
        if entry["mode"] == "rathole":
            group = group_name(entry)
            for path in (str(runtime.unit_dir / rathole_unit_name(group)), rathole_config_path(group, str(store.directory))):
                owners[path] = {f["tunnel"] for f in state["forwards"].values() if f["mode"] == "rathole" and group_name(f) == group}
    rows = []
    import base64
    for path, spec in expected.items():
        observed = ledger.file_value(path)
        if observed is None:
            continue
        wanted = {"content": base64.b64encode(spec["content"].encode()).decode(), "mode": spec["mode"]}
        if observed != wanted:
            raise StateError("Legacy generated artifact has foreign changes; preserving " + path)
        rows.append({"resource": "file:" + path, "type": "file", "owners": sorted(owners[path]), "observed": observed,
                     "provenance": {"source": "v1-exact-regeneration", "state_digest": digest(state), "content_digest": digest(wanted)}})
    table = runtime._table_snapshot("twinlink")
    if table is not None:
        if not nft_matches(render_nft(state), table):
            raise StateError("Legacy nft table differs from offline generated rules; preserving ip twinlink")
        checksum = digest(_canonical_nft(table))
        rows.append({"resource": "nft:twinlink", "type": "nft", "owners": sorted(state["tunnels"]), "observed": checksum,
                     "provenance": {"source": "v1-exact-regeneration", "state_digest": digest(state), "content_digest": checksum}})
    else:
        previous = ledger.read()["resources"].get("nft:twinlink")
        if previous and previous["status"] == "restoring" and previous["before"] is None:
            if previous["provenance"]["state_digest"] != digest(state):
                raise StateError("Interrupted legacy table removal belongs to another migration")
            rows.append({"resource": "nft:twinlink", "type": "nft", "owners": previous["owners"], "observed": None,
                         "provenance": previous["provenance"]})
    return rows


def adopt(store, runtime, rows):
    from .ownership import Ownership
    from .store import StateError
    ledger = Ownership(store)
    for row in rows:
        previous = ledger.read()["resources"].get(row["resource"])
        if row["type"] == "nft" and previous and previous["status"] in ("complete", "restoring"):
            if previous["provenance"] != row["provenance"]:
                raise StateError("Legacy table migration provenance changed")
            continue
        ledger.adopt(row["resource"], row["type"], row["owners"], row["observed"], row["provenance"])
    # All legacy runtime is off. Remove only the proven, empty legacy table;
    # file ownership remains reference counted until the last pair is deleted.
    row = next((row for row in rows if row["resource"] == "nft:twinlink"), None)
    if row:
        def remove(before):
            if before is not None:
                raise StateError("Unknown legacy nft baseline")
            runtime.host.run(["nft", "delete", "table", "ip", "twinlink"])
            return runtime._table_value("twinlink")
        for owner in ledger.read()["resources"]["nft:twinlink"]["owners"]:
            ledger.release("nft:twinlink", owner, runtime._table_value("twinlink"), remove)


def plan(state, transport_port=None):
    if state["version"] != 1:
        raise ValidationError("Migration requires v1 state")
    pairs, blockers = [], []
    roles = {t["side"] for t in state["tunnels"].values()}
    if len(roles) > 1:
        blockers.append("Mixed local roles require explicit operator grouping before migration")
    for name, tunnel in state["tunnels"].items():
        services = [f for f in state["forwards"].values() if f["tunnel"] == name]
        groups = {group_name(f) for f in services if f["mode"] == "rathole"}
        ports = {f["transport_port"] for f in services if f["mode"] == "rathole"}
        identities = {(f.get("token"), f.get("noise_public_key"), f.get("noise_private_key")) for f in services if f["mode"] == "rathole"}
        active = [f for f in services if f["running"] or f["enabled"]]
        reasons = []
        if tunnel["running"] or tunnel["enabled"] or active:
            reasons.append("Explicit offline cutover required: stop/disable legacy runtime on both hosts first")
        if len(ports) > 1 and transport_port is None:
            reasons.append("Review legacy transport consolidation and supply --transport-port")
        if len(identities) > 1:
            reasons.append("Different legacy service credentials/Noise identities require reviewed per-service migration")
        if any(f.get("rathole_transport", "tcp") != "noise" for f in services if f["mode"] == "rathole"):
            reasons.append("Legacy cleartext Rathole requires reviewed Noise identity generation")
        canonical_services = [{"id": f["name"], "bind": f["bind_address"], "protocol": f["protocol"],
            "ports": f["bind_port"], "backend": {"address": f["destination_address"], "ports": f["destination_port"]}, "probe": None} for f in services]
        side, peer = tunnel["side"], "vps2" if tunnel["side"] == "vps1" else "vps1"
        r = new_revision(name, {side: tunnel["local_public"], peer: tunnel["remote_public"]},
                         transport_port or (next(iter(ports)) if ports else 3456), canonical_services,
                         {"addresses": {side: tunnel["local_private"], peer: tunnel["remote_private"]},
                          "key": tunnel["key"], "mtu": tunnel["mtu"], "ttl": tunnel["ttl"]})
        if identities:
            r["public_keys"]["noise"] = next(iter(identities))[1]
        r["legacy_group_assignments"] = {f["name"]: {k: copy.deepcopy(f[k]) for k in ("rathole_group", "relay_port", "transport_port") if k in f} for f in services}
        pairs.append({"revision": r, "role": side, "legacy_groups": sorted(groups), "legacy_ports": sorted(ports),
                      "legacy_profile": sorted({f["mode"] for f in active}), "blockers": reasons})
        blockers.extend([name + ": " + reason for reason in reasons])
    return {"pairs": pairs, "blockers": blockers, "historical_baseline": "unknown; legacy restoration cannot be guaranteed",
            "runtime": "Migration stages profiles off; coordinated pairing and activation are separate"}
