import sqlite3

from fastapi.testclient import TestClient

from backend.main import app, DATABASE_PATH

client = TestClient(app)


def reset_db():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM conversations")
        conn.execute("DELETE FROM users")
        conn.commit()
    finally:
        conn.close()


def test_registration_login_and_encrypted_one_to_one_chat():
    reset_db()

    reg_alice = client.post(
        "/v1/register",
        json={"username": "alice", "password": "StrongPass123!"},
    )
    assert reg_alice.status_code == 200, reg_alice.text
    reg_bob = client.post(
        "/v1/register",
        json={"username": "bob", "password": "StrongPass456!"},
    )
    assert reg_bob.status_code == 200, reg_bob.text

    login_alice = client.post(
        "/v1/login",
        json={"username": "alice", "password": "StrongPass123!"},
    )
    assert login_alice.status_code == 200, login_alice.text
    login_bob = client.post(
        "/v1/login",
        json={"username": "bob", "password": "StrongPass456!"},
    )
    assert login_bob.status_code == 200, login_bob.text

    token_alice = login_alice.json()["token"]
    token_bob = login_bob.json()["token"]

    conv_resp = client.post(
        "/v1/conversations",
        json={"recipient_username": "bob"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert conv_resp.status_code == 200, conv_resp.text
    conversation_id = conv_resp.json()["conversation_id"]

    send_resp = client.post(
        "/v1/messages",
        json={"recipient_username": "bob", "content": "hello secret"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert send_resp.status_code == 200, send_resp.text

    fetch_resp = client.get(
        "/v1/messages",
        params={"with": "bob"},
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert fetch_resp.status_code == 200, fetch_resp.text
    payload = fetch_resp.json()
    assert payload[0]["content"] == "hello secret"

    conn = sqlite3.connect(DATABASE_PATH)
    try:
        row = conn.execute(
            "SELECT content FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT 1",
            (conversation_id,),
        ).fetchone()
        assert row is not None
        assert row[0] != "hello secret"
        assert "hello secret" not in row[0]
    finally:
        conn.close()

    unauthorized = client.get(
        "/v1/messages",
        params={"with": "bob"},
    )
    assert unauthorized.status_code == 401
