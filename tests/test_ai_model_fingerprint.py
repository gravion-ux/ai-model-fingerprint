import hashlib
import json

from ai_model_fingerprint import cli
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




def test_fingerprint_streams_large_file(tmp_path):
    target = tmp_path / "model.gguf"
    payload = b"GGUF" + b"x" * (2 * 1024 * 1024)
    target.write_bytes(payload)
    result = fingerprint(target)
    assert result.size == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    assert result.format == "GGUF"


def test_verify_manifest_is_case_insensitive(tmp_path):
    target = tmp_path / "model.bin"
    target.write_bytes(b"weights")
    digest = hashlib.sha256(b"weights").hexdigest().upper()
    assert verify_manifest({str(target): digest}) == []


def test_verify_manifest_rejects_directory_and_bad_digest(tmp_path):
    problems = verify_manifest({str(tmp_path): "abc", "x.bin": 42})
    assert any(p.startswith("missing:") for p in problems)
    assert any(p.startswith("invalid digest") for p in problems)


def test_cli_missing_file_is_usage_error(capsys):
    assert cli.main(["/nonexistent/model.gguf"]) == cli.EXIT_USAGE
    assert "cannot read" in capsys.readouterr().err


def test_cli_invalid_manifest_json_is_usage_error(tmp_path, capsys):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{not json", encoding="utf-8")
    assert cli.main(["--verify", str(manifest)]) == cli.EXIT_USAGE
    assert "invalid JSON" in capsys.readouterr().err
