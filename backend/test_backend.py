import base64
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = tmp_path / "cryptoshield-test.db"
    monkeypatch.setattr(main, "DATABASE_PATH", str(database_path))
    with TestClient(main.app) as test_client:
        yield test_client


def public_key(seed: int) -> str:
    return base64.urlsafe_b64encode(bytes([seed]) * 32).decode().rstrip("=")


def register(client: TestClient, username: str, offset: int) -> None:
    response = client.post(
        "/v1/register",
        json={
            "username": username,
            "password": "StrongPass123!",
            "encryption_public_key": public_key(offset),
            "signing_public_key": public_key(offset + 1),
        },
    )
    assert response.status_code == 200, response.text


def login(client: TestClient, username: str) -> str:
    response = client.post(
        "/v1/login",
        json={"username": username, "password": "StrongPass123!"},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def test_registration_login_and_ciphertext_relay(client):
    register(client, "alice", 1)
    register(client, "bob", 3)
    alice_token = login(client, "alice")
    bob_token = login(client, "bob")
    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    profile = client.get("/v1/me", headers=alice_headers)
    assert profile.status_code == 200
    assert profile.json()["encryption_public_key"] == public_key(1)
    assert "encryption_private_key" not in profile.json()

    bob_identity = client.get("/v1/users/bob/public-key", headers=alice_headers)
    assert bob_identity.status_code == 200
    assert bob_identity.json()["encryption_public_key"] == public_key(3)

    conversation = client.post(
        "/v1/conversations",
        json={"recipient_username": "bob"},
        headers=alice_headers,
    )
    assert conversation.status_code == 200, conversation.text

    ciphertext = '{"v":1,"ciphertext":"opaque-ciphertext"}'
    sent = client.post(
        "/v1/messages",
        json={"recipient_username": "bob", "ciphertext": ciphertext},
        headers=alice_headers,
    )
    assert sent.status_code == 200, sent.text
    assert "content" not in sent.json()

    fetched = client.get(
        "/v1/messages",
        params={"with": "alice"},
        headers=bob_headers,
    )
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()[0]["ciphertext"] == ciphertext
    assert "content" not in fetched.json()[0]

    listed = client.get("/v1/conversations", headers=bob_headers)
    assert listed.status_code == 200
    assert listed.json()[0]["other_username"] == "alice"

    conn = sqlite3.connect(main.DATABASE_PATH)
    try:
        stored_message = conn.execute("SELECT content FROM messages").fetchone()[0]
        stored_key = conn.execute("SELECT encryption_key FROM conversations").fetchone()[0]
        assert stored_message == ciphertext
        assert stored_key == ""
    finally:
        conn.close()


def test_authentication_and_key_validation(client):
    invalid_key = client.post(
        "/v1/register",
        json={
            "username": "alice",
            "password": "StrongPass123!",
            "encryption_public_key": "!" * 43,
            "signing_public_key": public_key(1),
        },
    )
    assert invalid_key.status_code == 400

    register(client, "alice", 1)
    assert client.get("/v1/me").status_code == 401
    wrong_password = client.post(
        "/v1/login",
        json={"username": "alice", "password": "WrongPassword123"},
    )
    assert wrong_password.status_code == 401


def test_users_cannot_open_self_conversation(client):
    register(client, "alice", 1)
    token = login(client, "alice")
    response = client.post(
        "/v1/conversations",
        json={"recipient_username": "alice"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
