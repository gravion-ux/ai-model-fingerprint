"""Fingerprint AI model files and verify integrity manifests."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

MAGICS = [
    (b"GGUF", "GGUF"),
    (b"\x50\x4b\x03\x04", "zip-container (PyTorch/ONNX zip)"),
]

HEADER_SCAN_BYTES = 1_000_000
CHUNK_SIZE = 1024 * 1024
MAX_EMBEDDED_URLS = 20

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")


def detect_format(data: bytes) -> str:
    """Detect the container format from a file header.

    ``data`` only needs to hold the first bytes of the file; safetensors
    detection reads the 8-byte little-endian header length that prefixes
    the JSON header.
    """
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    if len(data) >= 8:
        header_len = int.from_bytes(data[0:8], "little")
        if 0 < header_len <= len(data) - 8:
            try:
                header = json.loads(data[8 : 8 + header_len])
            except (ValueError, UnicodeDecodeError):
                return "unknown"
            return "safetensors" if isinstance(header, dict) else "unknown"
    return "unknown"


@dataclass
class Fingerprint:
    path: str
    size: int
    sha256: str
    format: str
    embedded_urls: list[str]


def fingerprint(path: str | Path) -> Fingerprint:
    """Hash a model file without loading it fully into memory.

    Model files are routinely gigabytes in size, so the digest is computed
    by streaming chunks; only the first megabyte is retained for format
    detection and embedded-URL extraction.
    """
    digest = hashlib.sha256()
    size = 0
    header = bytearray()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
            size += len(chunk)
            if len(header) < HEADER_SCAN_BYTES:
                header.extend(chunk[: HEADER_SCAN_BYTES - len(header)])
    urls = sorted({m.decode("ascii", "ignore") for m in URL_RE.findall(bytes(header))})
    return Fingerprint(
        str(path), size, digest.hexdigest(), detect_format(bytes(header)), urls[:MAX_EMBEDDED_URLS]
    )


def verify_manifest(manifest: dict) -> list[str]:
    """Return list of problems; empty means every entry matches."""
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object mapping paths to SHA-256 digests"]
    problems: list[str] = []
    for name, expected in manifest.items():
        if not isinstance(expected, str) or not expected.strip():
            problems.append(f"invalid digest for: {name}")
            continue
        p = Path(name)
        if not p.is_file():
            problems.append(f"missing: {name}")
            continue
        actual = fingerprint(p).sha256
        if actual.lower() != expected.strip().lower():
            problems.append(f"hash mismatch: {name}")
    return problems
