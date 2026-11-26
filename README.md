![ai-model-fingerprint banner](assets/banner.svg)

# ai-model-fingerprint

Defensive checker for AI model files: detects the container format
(GGUF, safetensors, zip-based), computes SHA-256 fingerprints, lists URLs
embedded in the file header region, and verifies model files against a
hash manifest so tampered or swapped weights are caught before loading.

Applied coursework for Red Team Leaders AI model reverse-engineering study —
used here defensively: know exactly which model bytes you are about to run.
It never executes model code.

## Install

```bash
pip install -e .
```

Requires Python 3.11+.

## Usage

```bash
ai-model-fingerprint model.gguf
ai-model-fingerprint --verify manifest.json
```

## Tests

```bash
pytest
```

## License

MIT
