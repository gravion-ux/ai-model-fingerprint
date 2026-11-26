"""CLI for ai-model-fingerprint."""
import argparse
import json
import sys
from pathlib import Path

from .fingerprint import fingerprint, verify_manifest


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Fingerprint AI model files / verify a hash manifest.")
    p.add_argument("paths", nargs="*", help="Model files to fingerprint")
    p.add_argument("--verify", metavar="MANIFEST", help="JSON manifest {path: sha256} to verify")
    args = p.parse_args(argv)
    if args.verify:
        manifest = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        problems = verify_manifest(manifest)
        if problems:
            for prob in problems:
                print(prob)
            return 1
        print("manifest OK")
        return 0
    out = []
    for raw in args.paths:
        fp = fingerprint(raw)
        out.append({"path": fp.path, "size": fp.size, "sha256": fp.sha256,
                    "format": fp.format, "embedded_urls": fp.embedded_urls})
    print(json.dumps(out, indent=2))
    return 0

if __name__ == "__main__":
    sys.exit(main())
