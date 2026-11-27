"""CLI for ai-model-fingerprint.

Exit codes: 0 = success / manifest OK, 1 = manifest problems found,
2 = usage or input error (reported as a one-line message, no traceback).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .fingerprint import fingerprint, verify_manifest

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai-model-fingerprint",
        description="Fingerprint AI model files / verify a hash manifest.",
    )
    parser.add_argument("paths", nargs="*", help="Model files to fingerprint")
    parser.add_argument("--verify", metavar="MANIFEST", help="JSON manifest {path: sha256} to verify")
    args = parser.parse_args(argv)

    if args.verify:
        try:
            manifest = json.loads(Path(args.verify).read_text(encoding="utf-8"))
        except OSError as exc:
            print(f"ai-model-fingerprint: cannot read manifest {args.verify}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_USAGE
        except json.JSONDecodeError as exc:
            print(f"ai-model-fingerprint: invalid JSON in {args.verify}: {exc.msg}", file=sys.stderr)
            return EXIT_USAGE
        problems = verify_manifest(manifest)
        if problems:
            for problem in problems:
                print(problem)
            return EXIT_PROBLEMS
        print("manifest OK")
        return EXIT_OK

    if not args.paths:
        parser.error("give at least one model file, or --verify MANIFEST")

    out = []
    for raw in args.paths:
        try:
            result = fingerprint(raw)
        except OSError as exc:
            print(f"ai-model-fingerprint: cannot read {raw}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_USAGE
        out.append({
            "path": result.path,
            "size": result.size,
            "sha256": result.sha256,
            "format": result.format,
            "embedded_urls": result.embedded_urls,
        })
    print(json.dumps(out, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
