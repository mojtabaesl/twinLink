"""Shared bounds for installer provenance and its runtime/cleanup readers."""
import json

from .contracts import strict_json

MAX_BASELINE_BYTES = 4 * 1024 * 1024
MAX_BASELINE_ITEMS = 65536


def parse(text):
    return strict_json(text, MAX_BASELINE_BYTES, max_items=MAX_BASELINE_ITEMS)


def serialize(value):
    text = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    parse(text)
    return text
