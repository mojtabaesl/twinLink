"""Durable manual two-host barriers. Never infer a live peer from a receipt."""
import copy
import hmac
import secrets
import time
import re

from .contracts import canonical, digest, fields, PROFILES
from .models import ValidationError
from .pair_bundle import mac
from .store import StateError


class Pending(RuntimeError):
    pass


def steps(profile):
    out = ([] if profile is None else [("vps1", "preflight"), ("vps2", "preflight")])
    out += [("vps1", "quiesce"), ("vps2", "quiesce")]
    if profile and profile.startswith("gre-"):
        out += [("vps1", "prepare"), ("vps2", "prepare")]
    if profile:
        first = "vps2" if profile in ("gre-kernel", "direct-paqet") else "vps1"
        second = "vps1" if first == "vps2" else "vps2"
        out += [(first, "start"), (second, "start"), ("vps2", "verify"), ("vps1", "verify")]
    out += [("vps2", "commit"), ("vps1", "commit"), ("vps2", "acknowledge"), ("vps1", "acknowledge")]
    return out


def new_transaction(pair, revision, profile, control, transaction_id=None, now=None, operation="switch"):
    if profile is not None and profile not in PROFILES:
        raise ValidationError("Unknown target profile")
    if control["role"] != "vps1" and profile is not None:
        raise ValidationError("Begin transitions on VPS1")
    return {"pair_id": pair, "revision": revision["revision"], "digest": digest(revision), "operation": operation,
            "target": profile, "previous": copy.deepcopy(control["active"]),
            "epoch": control.get("epoch", 0) + 1, "transaction_id": transaction_id or secrets.token_hex(16),
            "created_at": time.time() if now is None else now, "cursor": 0, "last_receipt": None,
            "local_completed": {}, "receipt_history": [], "phase": "local-withdrawal" if profile is None else "preflight", "error": None, "recovery_of": None}


def receipt_hash(value):
    return digest({k: value[k] for k in ("body", "hmac")})


def receipt(tx, role, step, key, now=None):
    timestamp = time.time() if now is None else now
    body = {k: tx[k] for k in ("pair_id", "revision", "digest", "target", "previous", "epoch", "transaction_id", "created_at", "recovery_of")}
    body["operation"] = tx.get("operation", "switch")
    body.update({"role": role, "step": step, "index": tx["cursor"], "nonce": secrets.token_hex(16),
                 "time": timestamp, "expires": timestamp + 300,
                 "previous_receipt_hash": receipt_hash(tx["last_receipt"]) if tx["last_receipt"] else None})
    return {"body": body, "hmac": mac(body, key), "history": copy.deepcopy(tx.get("receipt_history", []))}


def renew_receipt(value, key, now):
    """Renew delivery evidence without changing the phase's chain identity."""
    result = copy.deepcopy(value)
    body = {"receipt_hash": receipt_hash(value), "time": now, "expires": now + 300,
            "nonce": secrets.token_hex(16)}
    result["refresh"] = {"body": body, "hmac": mac(body, key)}
    return result


def validate_receipt(value, key, now=None):
    fields(value, ("body", "hmac"), ("history", "refresh"))
    if "history" in value and (not isinstance(value["history"], list) or len(value["history"]) > 20):
        raise ValidationError("Receipt history exceeds phase bounds")
    body = value["body"]
    fields(body, ("pair_id", "revision", "digest", "target", "previous", "epoch", "transaction_id", "created_at",
                  "role", "step", "index", "nonce", "time", "expires", "previous_receipt_hash", "recovery_of"), ("operation",))
    if body.get("operation", "switch") not in ("switch", "restart", "reapply", "recover"):
        raise ValidationError("Invalid receipt operation")
    if not isinstance(value["hmac"], str) or not hmac.compare_digest(mac(body, key), value["hmac"]):
        raise ValidationError("Receipt authentication failed")
    from .models import _name
    from .contracts import selection
    _name(body["pair_id"])
    if body["target"] is not None and body["target"] not in PROFILES:
        raise ValidationError("Invalid receipt target")
    for key_name in ("transaction_id", "nonce"):
        if not isinstance(body[key_name], str) or not re.fullmatch("[0-9a-f]{32}", body[key_name]):
            raise ValidationError("Invalid transaction/nonce")
    for key_name in ("revision", "epoch"):
        if type(body[key_name]) is not int or not 1 <= body[key_name] <= 2147483647:
            raise ValidationError("Invalid receipt revision/epoch")
    if not isinstance(body["digest"], str) or not re.fullmatch("[0-9a-f]{64}", body["digest"]):
        raise ValidationError("Invalid receipt digest")
    selection(body["previous"])
    timestamp = time.time() if now is None else now
    if any(type(body[k]) not in (int, float) for k in ("time", "expires", "created_at")):
        raise ValidationError("Invalid receipt times")
    if body["time"] > timestamp + 30 or body["expires"] - body["time"] != 300:
        raise ValidationError("Stale receipt or uncertain host clock; repeat preflight")
    refreshed = False
    if "refresh" in value:
        refresh = value["refresh"]
        fields(refresh, ("body", "hmac"))
        proof = refresh["body"]
        fields(proof, ("receipt_hash", "time", "expires", "nonce"))
        if (proof["receipt_hash"] != receipt_hash(value) or not isinstance(refresh["hmac"], str)
                or not hmac.compare_digest(mac(proof, key), refresh["hmac"])
                or not isinstance(proof["nonce"], str) or not re.fullmatch("[0-9a-f]{32}", proof["nonce"])
                or any(type(proof[k]) not in (int, float) for k in ("time", "expires"))
                or proof["time"] > timestamp + 30 or timestamp > proof["expires"]
                or proof["expires"] - proof["time"] != 300):
            raise ValidationError("Invalid or expired receipt refresh")
        refreshed = True
    if timestamp > body["expires"] and not refreshed:
        raise ValidationError("Stale receipt; ask the issuing host to refresh after revalidation")
    if type(body["index"]) is not int or not 0 <= body["index"] < len(steps(body["target"])):
        raise ValidationError("Invalid receipt phase")
    if steps(body["target"])[body["index"]] != (body["role"], body["step"]):
        raise ValidationError("Wrong receipt role or phase")
    return body


def consume(tx, incoming, key, now=None):
    body = validate_receipt(incoming, key, now)
    if body.get("operation", "switch") != tx.get("operation", "switch"):
        raise ValidationError("Receipt does not match transaction operation")
    for field in ("pair_id", "revision", "digest", "target", "previous", "epoch", "transaction_id", "created_at", "recovery_of"):
        if body[field] != tx[field]:
            raise ValidationError("Receipt does not match transaction " + field)
    if body["index"] != tx["cursor"]:
        raise ValidationError("Replayed or wrong-phase receipt")
    expected_hash = receipt_hash(tx["last_receipt"]) if tx["last_receipt"] else None
    if body["previous_receipt_hash"] != expected_hash:
        raise ValidationError("Receipt chain mismatch")
    tx["last_receipt"] = copy.deepcopy(incoming)
    tx.setdefault("receipt_history", []).append({k: copy.deepcopy(incoming[k]) for k in ("body", "hmac")})
    tx["cursor"] += 1


class Coordinator:
    """All callbacks must be idempotent; caller holds the local Store lock.

    Persist intent before side effects. Failures after quiescence never execute
    the legacy local snapshot rollback, which could resurrect an unsafe peer.
    """
    def __init__(self, store, runtime, clock=time.time):
        self.store, self.runtime, self.clock = store, runtime, clock

    @staticmethod
    def verified(tx):
        return {item["body"]["role"] for item in tx.get("receipt_history", [])
                if item["body"]["step"] == "verify"} == {"vps1", "vps2"}

    def verification_expired(self, tx):
        from .ownership import Ownership
        boot = Ownership.boot_id()
        monotonic_expired = (boot is not None and boot == tx.get("verification_boot_id")
                             and time.monotonic() >= tx.get("verification_monotonic_deadline", float("inf")))
        return self.clock() >= tx["verification_deadline"] or monotonic_expired

    def expire_verification(self, pair_id):
        """Systemd callback; caller holds the same mutation lock as advance."""
        state = self.store.read()
        control = state["pairs"][pair_id]
        tx = control["transition"]
        revision = self.store.revision(pair_id, tx["revision"] if tx else control["staged_revision"])
        if not tx or self.verified(tx):
            self.runtime.disarm_verification_expiry(revision, control["role"], (tx or {}).get("target"), control, tx or {})
            return {"status": "complete", "withdrawal": "No unverified target"}
        if "verification_deadline" not in tx:
            # Recovery/off can replace a pending activation journal before
            # withdrawal finishes. Its already-armed watchdog still protects
            # that exposure, even though the replacement has not started.
            if not self.runtime.verification_expiry_armed(revision, control["role"], tx["target"], control, tx):
                return {"status": "complete", "withdrawal": "No armed unverified target"}
        elif not self.verification_expired(tx):
            return {"status": "pending", "withdrawal": "Verification deadline has not elapsed"}
        if tx["target"] is not None:
            tx.update(phase="rollback-required", error="Verification deadline expired; target withdrawal required")
        self.store.write(state)
        try:
            local_tx = {**tx, "previous": tx.get("local_previous", tx["previous"])} if tx["target"] is None else tx
            self.runtime.quiesce(revision, control["role"], tx["target"], control, local_tx)
        except BaseException:
            tx["phase"] = "recovery-required"
            self.store.write(state)
            raise
        if tx["target"] is None:
            control["last_good"], control["active"], control["commit_pending"] = local_tx["previous"], None, True
        self.store.write(state)
        return {"status": "rollback-required" if tx["target"] is not None else "pending", "local_status": "off", "peer_cleanup": "unknown",
                "next_command": ("twinlink recover --rollback --pair " if tx["target"] is not None else "twinlink profile switch off --pair ") + pair_id + " --apply --yes"}

    def begin_recovery(self, pair_id):
        state = self.store.read()
        c = state["pairs"][pair_id]
        old = c["transition"]
        if c["role"] != "vps1" or not old:
            raise StateError("Begin coordinated rollback on VPS1 with a recorded transition")
        previous = old["previous"]
        r = self.store.revision(pair_id, previous["revision"] if previous else c["staged_revision"])
        target = previous["profile"] if previous else None
        tx = new_transaction(pair_id, r, target, c, now=self.clock(), operation="recover")
        tx.update(previous=previous, epoch=old["epoch"] + 1, recovery_of=old["transaction_id"])
        from .ownership import Ownership
        Ownership(self.store).write_file(self.store.directory / "journals" / ("recovery-" + pair_id + "-" + old["transaction_id"] + ".json"), canonical(old).decode(), pair_id)
        c["transition"] = tx
        self.store.write(state)
        return r, target

    def refresh_pending(self, state, control, revision, tx, key):
        saved = tx["last_receipt"]
        action = saved["body"]["step"]
        if action == "preflight" and self.clock() - tx["created_at"] > 300:
            raise ValidationError("Preflight evidence expired; cancel preflight on both hosts and begin again")
        tx["receipt_refresh"] = {"step": action, "status": "pending", "requested_at": self.clock()}
        self.store.write(state)
        try:
            readiness = self.runtime.revalidate(revision, control["role"], tx["target"], control, {**tx, "refresh_step": action})
            if action == "preflight" and isinstance(readiness, dict):
                tx["local_readiness"] = readiness
            if "verification_deadline" in tx and self.verification_expired(tx) and not self.verified(tx):
                raise StateError("Verification deadline expired during receipt revalidation")
            result = renew_receipt(saved, key, self.clock())
            from .ownership import Ownership
            Ownership(self.store).write_file(self.store.directory / "journals" / ("receipt-" + tx["pair_id"] + "-" + tx["transaction_id"] + ".json"), canonical(result).decode(), tx["pair_id"])
            tx["last_receipt"] = result
            tx["receipt_refresh"]["status"] = "complete"
            self.store.write(state)
            return {**self.progress(tx), "receipt": result, "receipt_refreshed_at": self.clock()}
        except Exception:
            tx["receipt_refresh"]["status"] = "failed"
            if action != "preflight":
                tx["phase"] = "rollback-required"
                try:
                    self.runtime.quiesce(revision, control["role"], tx["target"], control, tx)
                except Exception:
                    tx["phase"] = "recovery-required"
            self.store.write(state)
            raise

    def advance(self, pair_id, revision, target, incoming=None, transaction_id=None, step=None, operation=None, refresh=False):
        state = self.store.read()
        c = state["pairs"][pair_id]
        role, key = c["role"], self.store.credentials(pair_id)["management"]
        tx = c["transition"]
        if transaction_id is not None and (not isinstance(transaction_id, str) or not re.fullmatch("[0-9a-f]{32}", transaction_id)):
            raise ValidationError("Invalid transaction ID")
        operation = operation or (incoming or {}).get("body", {}).get("operation") or (tx or {}).get("operation", "switch")
        if operation not in ("switch", "restart", "reapply", "recover"):
            raise ValidationError("Invalid transition operation")
        # Validate replacement intent in memory. The watchdog must retain the
        # old transition until the replacement is atomically durable.
        superseded = None
        if target is None and tx and tx["target"] is not None:
            superseded = tx
            c["epoch"] = max(c["epoch"], tx["epoch"])
            c["transition"], tx = None, None

        def persist():
            nonlocal superseded
            if superseded is not None:
                from .ownership import Ownership
                Ownership(self.store).write_file(self.store.directory / "journals" / ("withdrawal-" + pair_id + "-" + superseded["transaction_id"] + ".json"), canonical(superseded).decode(), pair_id)
            self.store.write(state)
            superseded = None

        if target is None and role == "vps2" and incoming is None and (tx is None or tx.get("local_only")):
            if refresh or (step and step != "quiesce"):
                raise ValidationError("Local withdrawal requires the quiesce step")
            if tx and transaction_id and tx["transaction_id"] != transaction_id:
                raise StateError("Different transaction is already pending")
            if tx is None:
                tx = new_transaction(pair_id, revision, None, c, transaction_id, now=self.clock(), operation=operation)
                tx.update(local_only=True, phase="local-withdrawal", local_previous=copy.deepcopy(c["active"]))
                c["transition"] = tx
            persist()
            self.runtime.quiesce(revision, role, None, c, tx)
            c["last_good"], c["active"], c["commit_pending"] = tx["previous"], None, True
            tx["phase"] = "local-withdrawn"
            self.store.write(state)
            return {"status": "pending", "local_status": "off", "peer_cleanup": "pending", "next_host": "vps1",
                    "next_command": f"twinlink profile switch off --pair {pair_id} --apply --yes"}
        local_previous = copy.deepcopy((tx or {}).get("local_previous", c["active"]))
        if tx and tx.get("local_only") and incoming:
            tx = None
        if tx is None and incoming:
            body = validate_receipt(incoming, key, self.clock())
            if superseded is None and any(o.get("transaction_id") == body["transaction_id"] and o.get("epoch") == body["epoch"]
                   for o in c["peer_observations"]) and body["step"] == "acknowledge" and body["index"] == len(steps(target)) - 1:
                return {"status": "complete", "peer_evidence": "Repeated final acknowledgement; no runtime action"}
        if tx is None and superseded is None and role == "vps1" and transaction_id:
            path = self.store.directory / "journals" / ("receipt-" + pair_id + "-" + transaction_id + ".json")
            if path.exists():
                saved = self.store.private_read(path)
                body = saved["body"]
                if body["step"] != "acknowledge" or body["epoch"] != c["epoch"] or body["target"] != target or body.get("operation", "switch") != operation or (target is not None and body["digest"] != digest(revision)):
                    raise StateError("Completed transaction cannot be reused for a different operation")
                # Revalidate before renewing final acknowledgement delivery too.
                self.runtime.revalidate(revision, role, target, c, {**body, "refresh_step": "acknowledge"})
                saved = renew_receipt(saved, key, self.clock())
                from .ownership import Ownership
                Ownership(self.store).write_file(path, canonical(saved).decode(), pair_id)
                view = {**body, "cursor": len(steps(target)), "phase": "committed"}
                return {**self.progress(view), "receipt": saved}
        recovering = None
        if incoming and role == "vps2":
            b = validate_receipt(incoming, key, self.clock())
            if b["recovery_of"] and tx and b["recovery_of"] == tx["transaction_id"]:
                if b["previous"] != tx["previous"] or b["epoch"] != tx["epoch"] + 1:
                    raise ValidationError("Recovery receipt does not match saved rollback selection")
                recovering, tx = tx, None
        if tx is None:
            if role == "vps1":
                if incoming:
                    raise ValidationError("Unexpected receipt at transaction start")
                tx = new_transaction(pair_id, revision, target, c, transaction_id, self.clock(), operation)
            else:
                if incoming is None:
                    raise Pending("Await VPS1 preflight receipt")
                body = validate_receipt(incoming, key, self.clock())
                if body["pair_id"] != pair_id or body["index"] != 0 or (target is not None and (body["revision"] != revision["revision"] or body["digest"] != digest(revision))):
                    raise ValidationError("Initial receipt does not match staged revision")
                expected_previous = recovering["previous"] if recovering else c["active"]
                expected_epoch = recovering["epoch"] + 1 if recovering else c.get("epoch", 0) + 1
                if body["target"] != target or (target is not None and (body["previous"] != expected_previous or body["epoch"] != expected_epoch)) or (target is None and body["epoch"] <= c["epoch"]):
                    raise ValidationError("Peer selection/epoch differs; recover explicitly")
                tx = {k: copy.deepcopy(body[k]) for k in ("pair_id", "revision", "digest", "target", "previous", "epoch", "transaction_id", "created_at", "recovery_of")}
                tx["operation"] = body.get("operation", "switch")
                tx.update(cursor=0, last_receipt=None, local_completed={}, receipt_history=[], phase="local-withdrawal" if target is None else "preflight", error=None)
            tx.update(local_role=role, local_previous=local_previous)
            c["transition"] = tx
        if transaction_id and tx["transaction_id"] != transaction_id:
            raise StateError("Different transaction is already pending")
        if tx.get("operation", "switch") != operation or tx["target"] != target or (target is not None and tx["digest"] != digest(revision)):
            raise StateError("Cannot change target/revision within a transition")
        if tx["phase"] in ("rollback-required", "recovery-required"):
            raise StateError("Recovery required; runtime must remain withdrawn")
        # Re-importing an already accepted phase is idempotent, including when
        # retrying the original command to retrieve its lost outgoing receipt.
        if incoming and isinstance(incoming.get("body"), dict) and "hmac" in incoming:
            index = incoming["body"].get("index")
            if type(index) is int and 0 <= index < tx["cursor"] and receipt_hash(incoming) == receipt_hash(tx["receipt_history"][index]):
                expiry = incoming["body"]["expires"]
                if "refresh" in incoming:
                    try:
                        expiry = incoming["refresh"]["body"]["expires"]
                    except (TypeError, KeyError):
                        raise ValidationError("Invalid receipt refresh") from None
                    if type(expiry) not in (int, float):
                        raise ValidationError("Invalid receipt refresh expiry")
                validate_receipt(incoming, key, min(self.clock(), expiry))
                incoming = None
        if incoming:
            # Retrying the exact last import is harmless, never replays effects.
            if tx["last_receipt"] != incoming:
                validate_receipt(incoming, key, self.clock())
                history = incoming.get("history", [])
                if not isinstance(history, list) or len(history) > 20:
                    raise ValidationError("Receipt history exceeds phase bounds")
                chain = history + [{k: incoming[k] for k in ("body", "hmac")}]
                if len(chain) <= tx["cursor"]:
                    raise ValidationError("Replayed receipt")
                for i, item in enumerate(chain):
                    if i < tx["cursor"]:
                        if receipt_hash(item) != receipt_hash(tx["receipt_history"][i]):
                            raise ValidationError("Receipt history fork")
                    else:
                        if item["body"]["role"] == role:
                            raise ValidationError("Receipt claims a local step this host has not performed")
                        # Old signed phases remain evidence of ordering. Only
                        # the latest receipt must be fresh; preflight has its
                        # separate five-minute cutover deadline.
                        consume(tx, item, key, min(self.clock(), item["body"]["expires"]))
                tx["last_receipt"] = copy.deepcopy(incoming)
        sequence = steps(target)
        if target is not None and "verification_deadline" in tx and self.verification_expired(tx) and not self.verified(tx):
            self.expire_verification(pair_id)
            raise StateError("Verification deadline expired; target withdrawn, coordinated recovery required")
        if tx["cursor"] >= len(sequence):
            c["transition"] = None
            c["commit_pending"] = False
            c["peer_observations"] = [{"source": "authenticated-receipt-chain", "observed_at": self.clock(),
                "role": "vps1" if role == "vps2" else "vps2", "revision": tx["revision"],
                "digest": tx["digest"], "target": target, "epoch": tx["epoch"], "phase": "committed", "transaction_id": tx["transaction_id"]}]
            persist()
            return {"status": "complete", "peer_evidence": "Authenticated final acknowledgement"}
        expected_role, action = sequence[tx["cursor"]]
        latest = tx["last_receipt"]
        if latest and latest["body"]["role"] == role and (refresh or expected_role != role):
            if refresh and step and step != latest["body"]["step"]:
                raise ValidationError("Refresh the last completed local step: " + latest["body"]["step"])
            expires = latest.get("refresh", {}).get("body", latest["body"])["expires"]
            persist()
            if refresh or self.clock() > expires:
                return self.refresh_pending(state, c, revision, tx, key)
            return {**self.progress(tx), "receipt": copy.deepcopy(latest)}
        if refresh:
            raise ValidationError("No pending local receipt to refresh")
        if expected_role != role:
            persist()
            return self.progress(tx)
        if step and step != action:
            raise ValidationError("Expected step " + action)
        if target is not None and tx["cursor"] <= 2 and self.clock() - tx["created_at"] > 300:
            raise ValidationError("Preflight evidence expired; restart preparation before cutover")
        tx["phase"] = {"quiesce": "vps1-quiesced" if role == "vps1" else "both-quiesced",
            "start": "target-starting", "verify": "verifying", "commit": "committing"}.get(action, action)
        persist()
        try:
            if action == "start":
                if "verification_deadline" not in tx:
                    from .ownership import Ownership
                    tx.update(verification_deadline=self.clock() + 60,
                              verification_monotonic_deadline=time.monotonic() + 60,
                              verification_boot_id=Ownership.boot_id())
                self.store.write(state)
                self.runtime.arm_verification_expiry(revision, role, target, c, tx)
            if action in ("preflight", "quiesce", "prepare", "start", "verify"):
                local_tx = {**tx, "previous": tx.get("local_previous", tx["previous"])} if target is None else tx
                readiness = getattr(self.runtime, action)(revision, role, target, c, local_tx)
                if action == "preflight" and isinstance(readiness, dict):
                    tx["local_readiness"] = readiness
                if action == "verify" and self.verification_expired(tx):
                    raise StateError("Verification exceeded its original deadline")
                if target is None and action == "quiesce":
                    c["last_good"], c["active"], c["commit_pending"] = local_tx["previous"], None, True
            elif action == "commit":
                if target is not None:
                    self.runtime.disarm_verification_expiry(revision, role, target, c, tx)
                c["last_good"] = tx.get("local_previous", tx["previous"]) if target is None else tx["previous"]
                c["active"] = {"profile": target, "revision": tx["revision"], "epoch": tx["epoch"]} if target else None
                c["epoch"], c["commit_pending"] = tx["epoch"], True
            elif action == "acknowledge":
                # The final VPS1 receipt still has to reach VPS2.
                c["commit_pending"] = role == "vps2"
            result = receipt(tx, role, action, key, self.clock())
            tx["local_completed"][str(tx["cursor"])] = {k: copy.deepcopy(result[k]) for k in ("body", "hmac")}
            tx["last_receipt"] = result
            tx.setdefault("receipt_history", []).append({k: copy.deepcopy(result[k]) for k in ("body", "hmac")})
            tx["cursor"] += 1
            tx["error"] = None
            from .ownership import Ownership
            Ownership(self.store).write_file(self.store.directory / "journals" / ("receipt-" + pair_id + "-" + tx["transaction_id"] + ".json"), canonical(result).decode(), pair_id)
            if action == "acknowledge" and role == "vps1":
                # VPS1 has the peer's commit acknowledgement. Its own final
                # receipt is retained separately for retransmission to VPS2.
                c["peer_observations"] = [{"source": "authenticated-receipt-chain", "observed_at": self.clock(),
                    "role": "vps2", "revision": tx["revision"], "digest": tx["digest"], "target": target,
                    "epoch": tx["epoch"], "phase": "committed", "transaction_id": tx["transaction_id"]}]
                c["transition"] = None
            self.store.write(state)
        except Pending:
            # An operator can resume verification within the same budget.
            if action == "verify":
                tx.setdefault("verification_deadline", self.clock() + 60)
                self.store.write(state)
                if self.verification_expired(tx):
                    self.expire_verification(pair_id)
            raise
        except BaseException:
            tx["error"] = "Local step interrupted or failed; inspect diagnostics and recover"
            if action != "preflight":
                tx["phase"] = "rollback-required"
                try:
                    self.runtime.quiesce(revision, role, target, c, tx)
                except BaseException:
                    tx["phase"] = "recovery-required"
            self.store.write(state)
            raise
        return {**self.progress(tx), "receipt": result}

    @staticmethod
    def progress(tx):
        sequence = steps(tx["target"])
        if tx["cursor"] == len(sequence):
            next_role, action = "vps2", "acknowledge-final"
        else:
            next_role, action = sequence[tx["cursor"]]
        command = (f"twinlink recover --rollback --pair {tx['pair_id']}" if tx.get("recovery_of") else
                   f"twinlink profile {tx.get('operation', 'switch')}" + (f" {tx['target'] or 'off'}" if tx.get("operation", "switch") == "switch" else "") + f" --pair {tx['pair_id']}")
        if not tx.get("recovery_of"):
            command += f" --revision {tx['revision']}"
        withdrawal = {"local_status": "off", "peer_cleanup": "pending"} if tx["target"] is None and any(v["body"]["step"] == "quiesce" for v in tx.get("local_completed", {}).values()) else {}
        latest = tx.get("last_receipt")
        refresh = ({"refresh_command": f"{command} --transaction {tx['transaction_id']} --step {latest['body']['step']} --refresh-receipt --output NEW_RECEIPT --apply --yes"}
                   if latest and latest["body"]["role"] == tx.get("local_role") else {})
        return {"status": "pending", **withdrawal, **refresh, **({"local_readiness": tx["local_readiness"]} if "local_readiness" in tx else {}), "phase": tx["phase"], "transaction": tx["transaction_id"],
                "next_host": next_role, "next_step": action,
                "next_command": f"{command} --transaction {tx['transaction_id']} --step {action} --receipt-file RECEIPT --output NEXT_RECEIPT --apply --yes",
                "peer_evidence": "Timestamped authenticated receipt; peer is not queried live"}
