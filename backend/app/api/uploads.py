"""Read an upload with a hard size cap. Content checks happen in the parser."""

from pathlib import Path

from fastapi import UploadFile

from app.core.config import get_settings
from app.core.errors import AppError


async def read_eml_upload(file: UploadFile) -> bytes:
    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() != ".eml":
        raise AppError("unsupported_extension", "Only .eml files are accepted.", 400)
    return await read_bounded_upload(file, {".eml"})


async def read_bounded_upload(file: UploadFile, suffixes: set[str]) -> bytes:
    filename = Path(file.filename or "").name
    if not filename or Path(filename).suffix.lower() not in suffixes:
        raise AppError("unsupported_extension", "Only .eml and .mbox files are accepted.", 400)
    limit = get_settings().max_upload_bytes
    buffer = bytearray()
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        if len(buffer) + len(chunk) > limit:
            raise AppError("file_too_large", "The file exceeds the maximum allowed size.", 413)
        buffer.extend(chunk)
    data = bytes(buffer)
    if not data.strip():
        raise AppError("empty_file", "The uploaded file is empty.", 400)
    return data
