def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "phishcatch-soc"
    assert body["engine"] == "deterministic"
    assert body["reputation_enabled"] is False
    assert body["ai_enabled"] is False
    assert body["explainer_provider"] == "off"
    assert "api_key" not in response.text.lower()
