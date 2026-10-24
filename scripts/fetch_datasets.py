#!/usr/bin/env python3
"""Download the public corpora used by the evaluation. Does not crawl message links."""

from __future__ import annotations

import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "corpora"

FILES = (
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
        "easy_ham.tar.bz2",
        True,
    ),
    (
        "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
        "hard_ham.tar.bz2",
        True,
    ),
    ("https://monkey.org/~jose/phishing/phishing-2023", "nazario-phishing-2023.mbox", False),
    ("https://monkey.org/~jose/phishing/LICENSE.txt", "nazario-LICENSE.txt", False),
    ("https://monkey.org/~jose/phishing/README.txt", "nazario-README.txt", False),
)


def download(url: str, path: Path) -> None:
    if path.is_file() and path.stat().st_size > 0:
        print(f"keep {path.name}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"get {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "phishcatch-dataset-fetch"})
    with urllib.request.urlopen(request, timeout=120) as response:
        path.write_bytes(response.read())
    print(f"wrote {path.name} ({path.stat().st_size} bytes)")


def main() -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    for url, name, extract in FILES:
        target = DEST / name
        download(url, target)
        if extract:
            marker = DEST / ("easy_ham" if "easy_ham" in name else "hard_ham")
            if marker.is_dir() and any(marker.iterdir()):
                print(f"keep extracted {marker.name}")
                continue
            print(f"extract {name}")
            with tarfile.open(target, "r:bz2") as archive:
                archive.extractall(DEST)
    print(f"ready under {DEST}")
    print("These files are gitignored. Do not fetch URLs found inside the mail.")


if __name__ == "__main__":
    main()
