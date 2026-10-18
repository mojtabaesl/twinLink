"""Reviewed release identity; qualification is architecture/protocol specific.

Executable identity is NOT packet qualification. Never read this policy from
pair bundles. Evidence is pending until native Linux and systemd acceptance.
"""
from .contracts import PAQET_VERSION, PAQET_COMMIT

RELEASE_MANIFEST = {
    "version": PAQET_VERSION, "commit": PAQET_COMMIT,
    "identity_evidence": "https://api.github.com/repos/hanselime/paqet/releases/tags/" + PAQET_VERSION,
    "architectures": {
        "amd64": {"archive_sha256": "4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7",
                  "binary_sha256": "edb5d928443b3d47e5c7c86ae394dbac117826e7ddb7c27355fbd2cdd9ee1791"},
        "arm64": {"archive_sha256": "be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885",
                  "binary_sha256": "f6db279a57a772a250efffe4bb0a79b112495331568ccc0f6e5f4398bbe962e3"},
    },
    "qualification": {"amd64": {}, "arm64": {}},
    "evidence": "docs/paqet-qualification.md",
}
