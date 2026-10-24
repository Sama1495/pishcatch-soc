"""Allowlisted local samples for the one-click demo. No path from the client."""

from pathlib import Path

from app.core.errors import AppError

SAMPLES = Path(__file__).resolve().parents[3] / "samples"

# Names are the only client input. Values are paths relative to samples/.
_ALLOW = {
    "clearly_phishing": "clearly_phishing.eml",
    "clearly_benign": "clearly_benign.eml",
    "no_signals": "no_signals.eml",
    "ambiguous": "ambiguous.eml",
    "certification_lure": "certification_lure.eml",
    "certification_benign": "certification_benign.eml",
    "certification_lure_clean_auth": "certification_lure_clean_auth.eml",
    "corpus_phish_1": "demo-pack/corpus_phish_1.eml",
    "corpus_phish_2": "demo-pack/corpus_phish_2.eml",
    "corpus_ham_1": "demo-pack/corpus_ham_1.eml",
    "corpus_ham_2": "demo-pack/corpus_ham_2.eml",
}


def available() -> list[dict]:
    items = []
    for name, relative in _ALLOW.items():
        path = _resolve(relative)
        if path.is_file():
            items.append({"name": name, "filename": path.name, "bytes": path.stat().st_size})
    return items


def load(name: str) -> tuple[str, bytes]:
    relative = _ALLOW.get(name)
    if relative is None:
        raise AppError("not_found", "That demo sample is not in the allowlist.", 404)
    path = _resolve(relative)
    if not path.is_file():
        raise AppError("not_found", "That demo sample is not on disk.", 404)
    return path.name, path.read_bytes()


def _resolve(relative: str) -> Path:
    root = SAMPLES.resolve()
    path = (root / relative).resolve()
    if path != root and root not in path.parents:
        raise AppError("not_found", "That demo sample is not in the allowlist.", 404)
    return path
