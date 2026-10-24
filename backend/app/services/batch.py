"""Split an upload into messages. A zip is never opened."""

from pathlib import Path

MAX_BATCH_MESSAGES = 50


def split_upload(filename: str, raw: bytes) -> list[tuple[str, bytes]]:
    name = Path(filename or "message.eml").name or "message.eml"
    suffix = Path(name).suffix.lower()
    if suffix == ".mbox" or raw.startswith(b"From "):
        parts = _mbox_parts(raw)
        if parts:
            return [(f"{name}#{index + 1}", part) for index, part in enumerate(parts)]
    return [(name, raw)]


def _mbox_parts(raw: bytes) -> list[bytes]:
    current: list[bytes] = []
    parts: list[bytes] = []
    for line in raw.splitlines(keepends=True):
        if line.startswith(b"From ") and current:
            parts.append(b"".join(current))
            current = [line]
        else:
            current.append(line)
    if current and b"".join(current).strip():
        parts.append(b"".join(current))
    return parts
