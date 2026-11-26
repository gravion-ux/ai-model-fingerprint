import hashlib
import json

from ai_model_fingerprint.fingerprint import detect_format, fingerprint, verify_manifest


def test_detect_gguf():
    assert detect_format(b"GGUF" + b"\x00" * 32) == "GGUF"

def test_detect_safetensors():
    header = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    data = len(header).to_bytes(8, "little") + header + b"\x00\x00\x80\x3f"
    assert detect_format(data) == "safetensors"

def test_detect_unknown():
    assert detect_format(b"random bytes here") == "unknown"

def test_fingerprint_hash_and_urls(tmp_path):
    p = tmp_path / "model.bin"
    p.write_bytes(b"GGUF see https://example.com/docs for info")
    fp = fingerprint(p)
    assert fp.format == "GGUF"
    assert fp.sha256 == hashlib.sha256(p.read_bytes()).hexdigest()
    assert "https://example.com/docs" in fp.embedded_urls

def test_verify_manifest_ok_and_mismatch(tmp_path):
    p = tmp_path / "m.bin"
    p.write_bytes(b"abc")
    good = {str(p): hashlib.sha256(b"abc").hexdigest()}
    assert verify_manifest(good) == []
    bad = {str(p): "0" * 64}
    assert verify_manifest(bad)
    assert verify_manifest({str(tmp_path / "nope.bin"): "0" * 64})
