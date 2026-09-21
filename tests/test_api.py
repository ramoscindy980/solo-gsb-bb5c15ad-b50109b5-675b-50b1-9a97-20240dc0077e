import hashlib

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_redact_end_to_end():
    payload = {
        "data": {
            "users": [
                {"name": "amy", "password": "pw1", "ssn": "111"},
                {"name": "bob", "password": "pw2", "ssn": "222"},
            ],
            "debug": {"trace": True},
        },
        "rules": [
            {"path": "/users/*/password", "action": "mask"},
            {"path": "/users/**/ssn", "action": "sha256"},
            {"path": "/debug", "action": "remove"},
        ],
    }
    resp = client.post("/redact", json=payload)
    assert resp.status_code == 200
    body = resp.json()

    assert body["redacted"]["users"][0]["password"] == "***"
    assert body["redacted"]["users"][1]["password"] == "***"
    assert "debug" not in body["redacted"]
    assert body["redacted"]["users"][0]["ssn"] == hashlib.sha256(b"111").hexdigest()

    audit = body["audit"]
    assert {entry["pointer"] for entry in audit} == {
        "/users/0/password",
        "/users/1/password",
        "/users/0/ssn",
        "/users/1/ssn",
        "/debug",
    }
    for entry in audit:
        assert entry["action"] in {"mask", "remove", "sha256"}
        assert entry["applied"] is True
        assert isinstance(entry["rule"], str)
        assert isinstance(entry["rule_index"], int)


def test_salt_comes_from_environment(monkeypatch):
    monkeypatch.setenv("REDACT_SALT", "env-salt")
    payload = {"data": {"v": "x"}, "rules": [{"path": "/v", "action": "sha256"}]}
    resp = client.post("/redact", json=payload)
    assert resp.status_code == 200
    assert resp.json()["redacted"]["v"] == hashlib.sha256(b"env-saltx").hexdigest()


def test_invalid_action_rejected():
    payload = {"data": {}, "rules": [{"path": "/a", "action": "explode"}]}
    resp = client.post("/redact", json=payload)
    assert resp.status_code == 422


def test_invalid_pointer_rejected():
    payload = {"data": {}, "rules": [{"path": "a/b", "action": "mask"}]}
    resp = client.post("/redact", json=payload)
    assert resp.status_code == 422
    assert "invalid JSON Pointer" in resp.json()["detail"]


def test_empty_rules_and_scalar_document():
    resp = client.post("/redact", json={"data": 42, "rules": []})
    assert resp.status_code == 200
    assert resp.json() == {"redacted": 42, "audit": []}
