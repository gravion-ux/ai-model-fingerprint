"""Fingerprint AI model files and verify integrity manifests."""
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

MAGICS = [
    (b"GGUF", "GGUF"),
    (b"\x50\x4b\x03\x04", "zip-container (PyTorch/ONNX zip)"),
]

def detect_format(data: bytes) -> str:
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    if data[:1] == b"{":
        try:
            head = json.loads(data[: 8 + int.from_bytes(data[0:8], "little")] or b"{}")
            return "safetensors" if isinstance(head, dict) else "unknown"
        except (ValueError, UnicodeDecodeError):
            return "unknown"
    if len(data) >= 8:
        header_len = int.from_bytes(data[0:8], "little")
        if 0 < header_len <= len(data) - 8:
            try:
                json.loads(data[8:8 + header_len])
                return "safetensors"
            except (ValueError, UnicodeDecodeError):
                return "unknown"
    return "unknown"

@dataclass
class Fingerprint:
    path: str
    size: int
    sha256: str
    format: str
    embedded_urls: list

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")

def fingerprint(path) -> Fingerprint:
    data = Path(path).read_bytes()
    urls = sorted({m.decode("ascii", "ignore") for m in URL_RE.findall(data[: 1_000_000])})
    return Fingerprint(str(path), len(data), hashlib.sha256(data).hexdigest(),
                       detect_format(data), urls[:20])

def verify_manifest(manifest: dict) -> list[str]:
    """Return list of problems; empty means every entry matches."""
    problems = []
    for name, expected in manifest.items():
        p = Path(name)
        if not p.exists():
            problems.append(f"missing: {name}")
            continue
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual != expected:
            problems.append(f"hash mismatch: {name}")
    return problems
