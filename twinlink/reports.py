"""Report contracts, provenance-preserving merge, and epoch-aware comparison."""
import copy
from datetime import datetime
import math

from .models import ValidationError

MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_SAMPLES = 100000


def parse(text):
    """Watch reports have larger evidence arrays than configuration documents."""
    from .contracts import strict_json
    return validate(strict_json(text, MAX_REPORT_BYTES, max_items=MAX_SAMPLES))

REQUIRED = ("schema_version", "report_id", "created_at_utc", "collection_window", "collector_version", "versions", "host",
            "active_profile", "revisions", "config_digest", "service_mappings", "probes", "host_samples", "interface_route_samples",
            "firewall_conntrack", "processes_systemd", "profile_evidence", "log_events", "inactive_readiness", "overall_status",
            "findings", "collection_errors", "unknowns", "redaction_summary", "truncation")
EVIDENCE_BUCKETS = ("probes", "host_samples", "interface_route_samples", "firewall_conntrack", "processes_systemd", "profile_evidence")
EVIDENCE_FIELDS = ("id", "role", "observed_at_utc", "monotonic_offset", "source", "probe_definition", "result", "value", "unit", "expected_or_baseline", "error")
FINDING_TEXT = ("observation", "inference", "likely_cause")
FINDING_LISTS = ("evidence_ids", "counterevidence_ids", "suggested_next_checks")


def require(condition, path):
    if not condition:
        raise ValidationError("Invalid doctor report field: " + path)


def object_field(value, required, path):
    require(isinstance(value, dict) and not set(required) - set(value), path)


def string_field(value, path, nullable=False):
    require(isinstance(value, str) or (nullable and value is None), path)


def number_field(value, path):
    require((type(value) is int or type(value) is float and math.isfinite(value)) and value >= 0, path)


def timestamp(value, path):
    string_field(value, path)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise ValidationError("Invalid doctor report timestamp: " + path) from None
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None, path)
    return parsed


def array_field(value, path, limit=MAX_SAMPLES):
    require(isinstance(value, list) and len(value) <= limit, path)


def string_array(value, path):
    array_field(value, path)
    require(all(isinstance(item, str) for item in value), path)


def link_value(value, path):
    # Link snapshots are consumed by compare; other evidence values are opaque.
    if not isinstance(value, list):
        return
    for row in value:
        object_field(row, (), path)
        if "ifname" in row:
            string_field(row["ifname"], path + ".ifname")
        if "ifindex" in row:
            require(type(row["ifindex"]) is int and row["ifindex"] >= 0, path + ".ifindex")
        for name in ("stats", "stats64"):
            if name not in row:
                continue
            object_field(row[name], (), path + "." + name)
            for direction in ("rx", "tx"):
                if direction not in row[name]:
                    continue
                stats = row[name][direction]
                object_field(stats, (), path + "." + name + "." + direction)
                for counter in ("bytes", "packets", "errors", "dropped"):
                    if counter in stats:
                        require(type(stats[counter]) is int and stats[counter] >= 0, path + "." + counter)


def validate(report):
    object_field(report, REQUIRED, "report")
    require(type(report["schema_version"]) is int and report["schema_version"] == 1, "schema_version")
    require(type(report["collector_version"]) is int and report["collector_version"] >= 1, "collector_version")
    string_field(report["report_id"], "report_id")
    timestamp(report["created_at_utc"], "created_at_utc")
    require(report["overall_status"] in ("off", "healthy", "degraded", "failed", "unknown"), "overall_status")
    from .contracts import PROFILES
    require(report["active_profile"] is None or report["active_profile"] in PROFILES, "active_profile")
    string_field(report["config_digest"], "config_digest", nullable=True)
    for name in ("versions", "revisions"):
        object_field(report[name], (), name)
    host = report["host"]
    object_field(host, ("role", "pair_id", "boot_id", "clock"), "host")
    require(host["role"] in (None, "vps1", "vps2"), "host.role")
    for name in ("pair_id", "boot_id"):
        string_field(host[name], "host." + name, nullable=True)
    string_field(host["clock"], "host.clock")
    window = report["collection_window"]
    object_field(window, ("start", "end", "monotonic"), "collection_window")
    start = timestamp(window["start"], "collection_window.start")
    end = timestamp(window["end"], "collection_window.end")
    require(start <= end, "collection_window.end")
    object_field(window["monotonic"], ("start", "end"), "collection_window.monotonic")
    for name in ("start", "end"):
        number_field(window["monotonic"][name], "collection_window.monotonic." + name)
    require(window["monotonic"]["end"] >= window["monotonic"]["start"], "collection_window.monotonic.end")
    summary = report["redaction_summary"]
    object_field(summary, ("level", "context"), "redaction_summary")
    require(summary["level"] in ("share", "secrets"), "redaction_summary.level")
    string_field(summary["context"], "redaction_summary.context")
    for name, limit in (("service_mappings", 64), ("log_events", 800), ("inactive_readiness", MAX_SAMPLES), ("collection_errors", MAX_SAMPLES)):
        array_field(report[name], name, limit)
        for item in report[name]:
            object_field(item, (), name + "[]")
    for name in ("unknowns", "truncation"):
        string_array(report[name], name)
    for bucket in EVIDENCE_BUCKETS:
        array_field(report[bucket], bucket)
        for item in report[bucket]:
            object_field(item, EVIDENCE_FIELDS, bucket + "[]")
            for name in ("id", "source", "probe_definition"):
                string_field(item[name], bucket + "." + name)
            for name in ("role", "unit", "error"):
                string_field(item[name], bucket + "." + name, nullable=True)
            require(item["result"] in ("pass", "fail", "unknown"), bucket + ".result")
            timestamp(item["observed_at_utc"], bucket + ".observed_at_utc")
            number_field(item["monotonic_offset"], bucket + ".monotonic_offset")
            if "scheduling_gap" in item:
                number_field(item["scheduling_gap"], bucket + ".scheduling_gap")
            if bucket == "interface_route_samples" and item["source"] == "link" and item["result"] == "pass":
                link_value(item["value"], bucket + ".value")
    array_field(report["findings"], "findings")
    for finding in report["findings"]:
        object_field(finding, (*FINDING_TEXT, *FINDING_LISTS, "confidence"), "findings[]")
        for name in FINDING_TEXT:
            string_field(finding[name], "findings." + name)
        for name in FINDING_LISTS:
            string_array(finding[name], "findings." + name)
        require(finding["confidence"] in ("low", "medium", "high"), "findings.confidence")
    return report


def merge(first, second):
    validate(first)
    validate(second)
    if first["report_id"] == second["report_id"] or {first["host"]["role"], second["host"]["role"]} != {"vps1", "vps2"}:
        raise ValidationError("Paired merge requires distinct reports from opposite roles")
    # Per-report pseudonyms cannot prove host/pair identity across reports.
    if first["redaction_summary"]["level"] == "share" or second["redaction_summary"]["level"] == "share":
        raise ValidationError("Independent share pseudonyms cannot establish a matching pair; use private secrets-level local reports")
    if not first["host"]["pair_id"] or first["host"]["pair_id"] != second["host"]["pair_id"]:
        raise ValidationError("Reports refer to different or unknown pairs")
    starts = [timestamp(r["collection_window"]["start"], "collection_window.start") for r in (first, second)]
    ends = [timestamp(r["collection_window"]["end"], "collection_window.end") for r in (first, second)]
    if max(starts) > min(ends):
        raise ValidationError("Report collection windows do not overlap")
    from .diagnostics import evidence
    from .contracts import digest
    fields = ("config_digest", "active_profile", "service_mappings", "revisions")
    differences = [field for field in fields if digest(first[field]) != digest(second[field])]
    observations = [evidence("peer-configuration", "pass", {field: copy.deepcopy(r[field]) for field in fields},
                             0, r["host"]["role"]) for r in (first, second)]
    for observation, original in zip(observations, (first, second)):
        observation["observed_at_utc"] = original["created_at_utc"]
        observation["value"]["report_id"] = original["report_id"]
    findings = []
    if differences:
        findings.append({"observation": "Peer snapshots disagree on " + ", ".join(differences),
            "inference": "The reported configurations are not the same; both configuration snapshots are retained",
            "likely_cause": "Revision/selection disagreement or an edit during the collection windows",
            "evidence_ids": [o["id"] for o in observations], "counterevidence_ids": [], "confidence": "high",
            "suggested_next_checks": ["Compare active and staged revisions on both hosts before activation"]})
    return {"schema_version": 1, "kind": "paired-evidence", "reports": [copy.deepcopy(first), copy.deepcopy(second)],
            "provenance": [r["report_id"] for r in (first, second)], "overall_status": "degraded" if differences else "unknown",
            "profile_evidence": observations, "configuration_differences": differences, "findings": findings,
            "unknowns": ["Peer clock skew is unmeasured; precise cross-host ordering is unavailable"]}


def compare(old, new):
    validate(old)
    validate(new)
    same_epoch = bool(old["host"]["boot_id"]) and old["host"]["boot_id"] == new["host"]["boot_id"]
    same_pair = old["host"]["pair_id"] == new["host"]["pair_id"] and old["host"]["pair_id"] is not None
    if old["redaction_summary"]["level"] == "share" or new["redaction_summary"]["level"] == "share":
        raise ValidationError("Cannot compare identity across unrelated share pseudonyms")
    deltas, unknowns = [], []
    def interfaces(report):
        rows = {}
        for item in report["interface_route_samples"]:
            if item["source"] == "link" and item["result"] == "pass" and isinstance(item["value"], list):
                rows.update({r["ifname"]: r for r in item["value"] if "ifname" in r})
        return rows
    before, after = interfaces(old), interfaces(new)
    if same_epoch and same_pair:
        for interface in sorted(before.keys() | after.keys()):
            a, b = before.get(interface), after.get(interface)
            if not a or not b or "ifindex" not in a or a["ifindex"] != b.get("ifindex"):
                unknowns.append("Missing or changed interface epoch: " + interface)
                continue
            for direction in ("rx", "tx"):
                astats = a.get("stats64", a.get("stats", {})).get(direction, {})
                bstats = b.get("stats64", b.get("stats", {})).get(direction, {})
                for counter in ("bytes", "packets", "errors", "dropped"):
                    x, y = astats.get(counter), bstats.get(counter)
                    valid = type(x) is int and type(y) is int and y >= x
                    deltas.append({"interface": interface, "counter": direction + "." + counter,
                                   "result": "pass" if valid else "unknown", "delta": y - x if valid else None})
    else:
        unknowns.append("Different or unknown boot/pair identity; counter deltas suppressed")
    return {"schema_version": 1, "kind": "comparison", "provenance": [old["report_id"], new["report_id"]],
            "status_before": old["overall_status"], "status_after": new["overall_status"],
            "same_boot": same_epoch, "same_pair": same_pair, "counter_deltas": deltas,
            "unknowns": unknowns}
