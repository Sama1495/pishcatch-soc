from tests.paths import SAMPLES


def _error(response):
    body = response.json()
    assert set(body.keys()) == {"error"}
    assert set(body["error"].keys()) == {"code", "message", "details"}
    assert isinstance(body["error"]["message"], str)
    assert body["error"]["message"]
    return body["error"]


def test_rejects_empty_file(client):
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("empty.eml", (SAMPLES / "empty.eml").read_bytes(), "message/rfc822")},
    )
    assert response.status_code == 400
    assert _error(response)["code"] == "empty_file"


def test_rejects_whitespace_file(client):
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("blank.eml", b" \n\t\n", "message/rfc822")},
    )
    assert response.status_code == 400
    assert _error(response)["code"] == "empty_file"


def test_rejects_wrong_extension(client):
    payload = (SAMPLES / "clearly_benign.eml").read_bytes()
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("notes.txt", payload, "text/plain")},
    )
    assert response.status_code == 400
    assert _error(response)["code"] == "unsupported_extension"


def test_rejects_double_extension_that_is_not_eml(client):
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("invoice.eml.exe", b"From: a@contoso.example\n\nHi\n", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert _error(response)["code"] == "unsupported_extension"


def test_rejects_malformed_sample(client):
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("malformed.eml", (SAMPLES / "malformed.eml").read_bytes(), "message/rfc822")},
    )
    assert response.status_code == 400
    error = _error(response)
    assert error["code"] == "invalid_content"
    assert "Traceback" not in response.text
    assert "RFC 5322" not in error["message"]


def test_rejects_binary_disguised_as_eml(client):
    payload = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("photo.eml", payload, "message/rfc822")},
    )
    assert response.status_code == 400
    assert _error(response)["code"] == "invalid_content"


def test_rejects_oversize_file(client):
    header = b"From: a@contoso.example\r\nSubject: oversized\r\n\r\n"
    payload = header + (b"A" * (1_048_576))
    assert len(payload) > 1_048_576
    response = client.post(
        "/api/v1/incidents",
        files={"file": ("big.eml", payload, "message/rfc822")},
    )
    assert response.status_code == 413
    assert _error(response)["code"] == "file_too_large"


def test_missing_file_uses_uniform_error(client):
    response = client.post("/api/v1/incidents")
    assert response.status_code == 422
    assert _error(response)["code"] == "validation_error"
