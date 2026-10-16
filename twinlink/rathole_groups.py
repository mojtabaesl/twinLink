"""Shared Rathole process identities; legacy entries retain their own identity."""


def group_name(entry):
    return entry.get("rathole_group", entry["name"])


def groups(state):
    result = {}
    for name, entry in sorted(state["forwards"].items()):
        if name != entry["name"]:
            raise ValueError("forward name does not match its state key")
        if entry["mode"] == "rathole":
            result.setdefault(group_name(entry), []).append(entry)
    return result


def unit_name(entry):
    return "twinlink-rathole-" + group_name(entry) + ".service"


def units(state, names=None):
    return {unit_name(entry) for name, entry in state["forwards"].items()
            if entry["mode"] == "rathole" and (names is None or name in names)}
