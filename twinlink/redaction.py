"""Allowlisted report scrubbing and consistent private pseudonyms."""
import hashlib
import hmac
import re
import secrets

SECRET_KEYS = frozenset(("key", "token", "default_token", "password", "secret", "credentials", "management",
                         "rathole", "paqet", "noise_private", "noise_private_key", "local_private_key", "request_hex", "response_hex"))
IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PRIVATE_FIELDS = frozenset(("pair_id", "boot_id", "hostname", "provider", "interface", "ifname", "dev", "port", "ports", "transport_port",
                            "source_port", "destination_port", "pid", "pids", "name", "resource", "path", "state_directory", "installation_id"))
PORT_FIELDS = frozenset(("port", "ports", "transport_port", "source_port", "destination_port", "sport", "dport"))
WORDS = re.compile(r"[\w-]+")
OWNERSHIP_MARKER = re.compile(r"\btwinlink:([A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)")
UUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")


def scrub_assignments(value):
    """Scan names and values once, without overlapping wildcard searches."""
    chunks, consumed = [], 0
    for match in WORDS.finditer(value):
        if match.start() < consumed:
            continue
        name = match.group().casefold()
        if not any(key in name for key in ("key", "token", "password", "secret")):
            continue
        cursor = match.end()
        # Accept quoted JSON keys as well as unquoted log assignments.
        if match.start() and value[match.start() - 1] in "\"'" and cursor < len(value) and value[cursor] == value[match.start() - 1]:
            cursor += 1
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        if cursor == len(value) or value[cursor] not in "=:":
            continue
        cursor += 1
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        start = cursor
        if cursor == len(value):
            continue
        if value[cursor] in "\"'":
            quote = value[cursor]
            cursor += 1
            while cursor < len(value) and value[cursor] not in "\r\n":
                if value[cursor] == quote:
                    cursor += 1
                    break
                if value[cursor] == "\\" and cursor + 1 < len(value) and value[cursor + 1] not in "\r\n":
                    cursor += 1
                cursor += 1
        else:
            while cursor < len(value) and not value[cursor].isspace() and value[cursor] != ",":
                cursor += 1
        chunks.extend((value[consumed:start], '"<redacted>"'))
        consumed = cursor
    chunks.append(value[consumed:])
    return "".join(chunks)


class Redactor:
    def __init__(self, level="share", known_secrets=(), context=None):
        if level not in ("share", "secrets"):
            raise ValueError("Unknown redaction level")
        self.level = level
        self.context = context or secrets.token_bytes(32)
        self.known = tuple(sorted({s for s in known_secrets if isinstance(s, str) and s}, key=len, reverse=True))

    def pseudonym(self, value, kind="value"):
        return kind + "-" + hmac.new(self.context, str(value).encode(), hashlib.sha256).hexdigest()[:12]

    def ownership_marker(self, match):
        parts = match[1].split(":")
        if UUID.fullmatch(parts[0]):
            result = "twinlink:" + self.pseudonym(parts[0], "installation_id")
            if len(parts) > 1:
                result += ":" + self.pseudonym(parts[1], "pair_id")
            if len(parts) > 2:
                result += ":" + self.pseudonym(":".join(parts[2:]), "resource")
            return result
        return "twinlink:" + self.pseudonym(match[1], "resource")

    def operand(self, value, kind):
        """Scrub typed nft operands without turning counters into ports."""
        if isinstance(value, list):
            return [self.operand(item, kind) for item in value]
        if isinstance(value, dict):
            if set(value) == {"range"} and isinstance(value["range"], list) and len(value["range"]) == 2 and kind == "port":
                lo, hi = value["range"]
                if all(type(item) is int and 0 <= item <= 65535 for item in (lo, hi)) and lo <= hi:
                    return {"range": {"start": self.pseudonym(lo, "port"), "width": hi - lo + 1}}
            if set(value) in ({"range"}, {"set"}):
                return {name: self.operand(child, kind) for name, child in value.items()}
            # Opaque expressions must not leak unrecognized operand leaves.
            return self.pseudonym(value, kind)
        if value is None:
            return None
        if kind == "port" and isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}", value):
            lo, hi = map(int, value.split("-"))
            if lo <= hi <= 65535:
                return {"start": self.pseudonym(lo, "port"), "width": hi - lo + 1}
        return self.pseudonym(value, kind)

    def string(self, value):
        for secret in self.known:
            value = value.replace(secret, "<redacted>")
        value = re.sub(r"\b(?:p2|r1|f1|v1)\.[A-Za-z0-9_=-]+", "<redacted-bundle>", value)
        value = scrub_assignments(value)
        if self.level == "share":
            value = OWNERSHIP_MARKER.sub(self.ownership_marker, value)
            value = re.sub(r"\b((?:service|backend):[^:\s]+:)(\d+)\b", lambda m: m[1] + self.pseudonym(m[2], "port"), value)
            value = IP.sub(lambda match: self.pseudonym(match.group(), "ip"), value)
            value = re.sub(r"((?:ip-[0-9a-f]{12}|\*|\[::\]):)([0-9]{1,5})\b",
                           lambda m: m[1] + self.pseudonym(m[2], "port"), value)
            value = re.sub(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", lambda m: self.pseudonym(m.group(), "mac"), value)
        return value

    def scrub(self, value, field=None):
        if field in SECRET_KEYS and (field not in ("rathole", "paqet") or isinstance(value, str)):
            return "<redacted>"
        if self.level == "share" and field in PORT_FIELDS:
            return self.operand(value, "port")
        if self.level == "share" and field in ("ifalias", "alias") and isinstance(value, str):
            return self.string(value) if value.startswith("twinlink:") else self.pseudonym(value, "ifalias")
        if isinstance(value, dict):
            result = {self.string(str(k)): self.scrub(v, str(k)) for k, v in value.items()}
            if field == "match" and isinstance(value.get("left"), dict) and "right" in value:
                left = value["left"]
                payload, meta = left.get("payload"), left.get("meta")
                if self.level == "share" and isinstance(payload, dict) and payload.get("field") in ("sport", "dport"):
                    result["right"] = self.operand(value["right"], "port")
                elif isinstance(meta, dict) and meta.get("key") in ("iifname", "oifname"):
                    if self.level == "share":
                        result["right"] = self.operand(value["right"], "ifname")
                    # This key names a selector, rather than a credential.
                    result["left"]["meta"]["key"] = meta["key"]
                elif self.level == "share" and isinstance(meta, dict) and meta.get("key") == "<redacted>":
                    # Older private reports lost this selector. Hide the
                    # operand opaquely rather than guessing its public type.
                    result["right"] = self.operand(value["right"], "operand")
            return result
        if isinstance(value, list):
            return [self.scrub(v, field) for v in value]
        if self.level == "share" and field in PRIVATE_FIELDS and value is not None:
            return self.pseudonym(value, "port" if "port" in field else field)
        if isinstance(value, str):
            return self.string(value)
        return value


def secret_values(value):
    out = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SECRET_KEYS and isinstance(child, str):
                out.append(child)
            out.extend(secret_values(child))
    elif isinstance(value, list):
        for child in value:
            out.extend(secret_values(child))
    return out


def stored_secrets(store):
    """Include retained active/rollback credentials while another revision is staged."""
    state = store.read()
    values = secret_values(state)
    if state["version"] == 2:
        for pair, control in state["pairs"].items():
            numbers = {control["staged_revision"]}
            root = store.revision_path(pair, 1).parent
            if root.exists():
                numbers.update(int(p.name) for p in root.iterdir() if p.name.isdigit() and (p / "credentials.json").exists())
            for number in numbers:
                values.extend(secret_values(store.credentials(pair, number)))
    return values
