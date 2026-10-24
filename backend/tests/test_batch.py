from tests.paths import SAMPLES


def test_batch_accepts_eml_and_records_a_bad_file(client):
    good = (SAMPLES / "no_signals.eml").read_bytes()
    response = client.post(
        "/api/v1/incidents/batch",
        files=[
            ("files", ("no_signals.eml", good, "message/rfc822")),
            ("files", ("notes.zip.eml", b"PK\x03\x04not-opened", "message/rfc822")),
            ("files", ("notes.txt", good, "text/plain")),
        ],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 1
    assert body["failed"] == 2
    codes = {item["error_code"] for item in body["items"]}
    assert None in codes
    assert "invalid_content" in codes
    assert "unsupported_extension" in codes


def test_mbox_is_split_and_demo_pack_is_allowlisted(client):
    one = (SAMPLES / "no_signals.eml").read_bytes()
    two = (SAMPLES / "ambiguous.eml").read_bytes()
    if not one.startswith(b"From "):
        one = b"From mailbox Sat Oct 24 00:00:00 2026\n" + one
    if not two.startswith(b"From "):
        two = b"From mailbox Sat Oct 24 00:00:01 2026\n" + two
    mbox = one + b"\n" + two
    response = client.post(
        "/api/v1/incidents/batch",
        files=[("files", ("inbox.mbox", mbox, "application/mbox"))],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 2
    assert body["failed"] == 0

    missing = client.post("/api/v1/demo-pack/not-a-sample/analyze")
    assert missing.status_code == 404
    listed = client.get("/api/v1/demo-pack")
    assert listed.status_code == 200
    names = {item["name"] for item in listed.json()["items"]}
    assert "certification_lure_clean_auth" in names
    created = client.post("/api/v1/demo-pack/certification_lure_clean_auth/analyze")
    assert created.status_code == 201, created.text
    assert created.json()["risk_label"] == "likely_malicious"
    assert "person" not in created.json()["timeline"][-1]["provenance"].get("tool", "")
