"""Score a fixed sample of public corpora with the live parse/rules/risk path.

This module does not fetch URLs found inside messages and does not render HTML.
Numbers written by ``main`` are counts from that run. They are not estimates.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from email.errors import MessageError
from pathlib import Path

from app.services.exceptions import ParseRejection
from app.services.parser import parse_eml
from app.services.risk import classify
from app.services.rules import RULESET_VERSION, evaluate

REPO = Path(__file__).resolve().parents[2]
CORPORA = REPO / "data" / "corpora"
PHISH_LIMIT = 200
EASY_LIMIT = 200
HARD_LIMIT = 100


def iter_mbox(path: Path):
    """Yield raw messages. A line that begins with ``From `` starts a new one."""
    current: list[bytes] = []
    with path.open("rb") as handle:
        for line in handle:
            if line.startswith(b"From ") and current:
                yield b"".join(current)
                current = [line]
            else:
                current.append(line)
        if current and b"".join(current).strip():
            yield b"".join(current)


def _ham_files(folder: Path, limit: int) -> list[Path]:
    files = sorted(path for path in folder.rglob("*") if path.is_file() and not path.name.startswith("."))
    return files[:limit]


def _score_bytes(raw: bytes) -> tuple[str, float]:
    started = time.perf_counter()
    parsed = parse_eml(raw)
    hits = evaluate(parsed)
    label = classify(hits).label
    elapsed_ms = (time.perf_counter() - started) * 1000
    return label, elapsed_ms


def _consume(items, kind: str) -> dict:
    labels = {"likely_malicious": 0, "suspicious": 0, "likely_benign": 0, "inconclusive": 0}
    failures = 0
    failure_codes: dict[str, int] = {}
    latencies: list[float] = []
    seen = 0
    for raw in items:
        seen += 1
        try:
            label, elapsed = _score_bytes(raw)
        except ParseRejection as exc:
            failures += 1
            failure_codes[exc.code] = failure_codes.get(exc.code, 0) + 1
            continue
        except (MessageError, UnicodeError, ValueError, RecursionError) as exc:
            failures += 1
            failure_codes[type(exc).__name__] = failure_codes.get(type(exc).__name__, 0) + 1
            continue
        labels[label] = labels.get(label, 0) + 1
        latencies.append(elapsed)
    return {
        "kind": kind,
        "attempted": seen,
        "scored": seen - failures,
        "failures": failures,
        "failure_codes": failure_codes,
        "labels": labels,
        "latencies_ms": latencies,
    }


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return round(ordered[index], 3)


def _rates(phishing: dict, ham_sets: list[dict]) -> dict:
    """Binary rates treat malicious and suspicious as the positive prediction.

    Inconclusive is reported on its own and is not counted as a true negative
    or a true positive. Ham that is inconclusive is not a false positive.
    """
    phish_labels = phishing["labels"]
    tp = phish_labels["likely_malicious"] + phish_labels["suspicious"]
    fn = phish_labels["likely_benign"]
    phish_inc = phish_labels["inconclusive"]
    fp = 0
    tn = 0
    ham_inc = 0
    ham_scored = 0
    ham_attempted = 0
    for ham in ham_sets:
        labels = ham["labels"]
        fp += labels["likely_malicious"] + labels["suspicious"]
        tn += labels["likely_benign"]
        ham_inc += labels["inconclusive"]
        ham_scored += ham["scored"]
        ham_attempted += ham["attempted"]
    phish_scored = phishing["scored"]
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "phishing_inconclusive": phish_inc,
        "ham_inconclusive": ham_inc,
        "tpr": None if phish_scored == 0 else tp / phish_scored,
        "fnr": None if phish_scored == 0 else fn / phish_scored,
        "fpr": None if ham_scored == 0 else fp / ham_scored,
        "tnr": None if ham_scored == 0 else tn / ham_scored,
        "inconclusive_rate_phishing": None if phish_scored == 0 else phish_inc / phish_scored,
        "inconclusive_rate_ham": None if ham_scored == 0 else ham_inc / ham_scored,
        "phishing_scored": phish_scored,
        "phishing_attempted": phishing["attempted"],
        "ham_scored": ham_scored,
        "ham_attempted": ham_attempted,
    }


def run() -> dict:
    phish_path = CORPORA / "nazario-phishing-2023.mbox"
    easy = CORPORA / "easy_ham"
    hard = CORPORA / "hard_ham"
    if not phish_path.is_file() or not easy.is_dir() or not hard.is_dir():
        raise SystemExit(
            "Corpora are missing. Run scripts/fetch_datasets.py first. "
            "Expected data/corpora/nazario-phishing-2023.mbox, easy_ham/, and hard_ham/."
        )
    phish_raw = list(iter_mbox(phish_path))[:PHISH_LIMIT]
    easy_raw = [path.read_bytes() for path in _ham_files(easy, EASY_LIMIT)]
    hard_raw = [path.read_bytes() for path in _ham_files(hard, HARD_LIMIT)]
    phishing = _consume(phish_raw, "nazario-phishing-2023")
    easy_result = _consume(easy_raw, "spamassassin-easy-ham-20030228")
    hard_result = _consume(hard_raw, "spamassassin-hard-ham-20030228")
    latencies = phishing["latencies_ms"] + easy_result["latencies_ms"] + hard_result["latencies_ms"]
    rates = _rates(phishing, [easy_result, hard_result])
    failures = phishing["failures"] + easy_result["failures"] + hard_result["failures"]

    def public_slice(result: dict) -> dict:
        return {key: value for key, value in result.items() if key != "latencies_ms"}

    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "ruleset": RULESET_VERSION,
        "selection": (
            f"First {PHISH_LIMIT} messages in mailbox order from nazario-phishing-2023; "
            f"first {EASY_LIMIT} easy_ham files and first {HARD_LIMIT} hard_ham files by sorted path. "
            "Not a random sample and not tuned after looking at errors."
        ),
        "datasets": [
            {
                "name": "Jose Nazario phishing corpus",
                "file": "phishing-2023",
                "url": "https://monkey.org/~jose/phishing/phishing-2023",
                "license": "CC-BY-4.0",
                "role": "phishing",
                "attempted": phishing["attempted"],
            },
            {
                "name": "SpamAssassin public corpus easy_ham",
                "file": "20030228_easy_ham.tar.bz2",
                "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
                "license": "Public corpus. Copyright in the messages remains with the senders.",
                "role": "ham",
                "attempted": easy_result["attempted"],
            },
            {
                "name": "SpamAssassin public corpus hard_ham",
                "file": "20030228_hard_ham.tar.bz2",
                "url": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
                "license": "Public corpus. Copyright in the messages remains with the senders.",
                "role": "ham",
                "attempted": hard_result["attempted"],
            },
        ],
        "positive_prediction": ["likely_malicious", "suspicious"],
        "rates": rates,
        "failures_handled": failures,
        "latency_ms": {
            "p50": _percentile(latencies, 50),
            "p95": _percentile(latencies, 95),
            "n": len(latencies),
        },
        "slices": {
            "phishing": public_slice(phishing),
            "easy_ham": public_slice(easy_result),
            "hard_ham": public_slice(hard_result),
        },
        "note": (
            "Rates use scored messages only. Inconclusive is not treated as benign "
            "and is not a true positive. No URL inside a message was fetched."
        ),
    }


def main() -> None:
    report = run()
    text = json.dumps(report, indent=2)
    out = Path(__file__).resolve().parent / "evaluation" / "latest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + "\n", encoding="utf-8")
    print(text)
    print(f"wrote {out}", flush=True)


if __name__ == "__main__":
    main()
