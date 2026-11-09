from fastapi.testclient import TestClient

from backend import main


def test_accounts_admin_controls_and_private_messages(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "VeryStrongAdminPass123!")

    with TestClient(main.app) as client:
        admin_login = client.post(
            "/v1/login",
            json={
                "username": "ADMIN@example.com",
                "password": "VeryStrongAdminPass123!",
            },
        )
        assert admin_login.status_code == 200
        assert admin_login.json()["user"]["role"] == "admin"
        admin_headers = {
            "Authorization": f"Bearer {admin_login.json()['token']}"
        }

        reg_alice = client.post(
            "/v1/register",
            json={
                "username": "alice@example.com",
                "password": "StrongPass123!abc",
            },
        )
        assert reg_alice.status_code == 200, reg_alice.text
        reg_bob = client.post(
            "/v1/register",
            json={
                "username": "bob@example.com",
                "password": "StrongPass456!abc",
            },
        )
        assert reg_bob.status_code == 200, reg_bob.text

        login_alice = client.post(
            "/v1/login",
            json={
                "username": "ALICE@example.com",
                "password": "StrongPass123!abc",
            },
        )
        assert login_alice.status_code == 200
        alice_headers = {
            "Authorization": f"Bearer {login_alice.json()['token']}"
        }

        admin_overview = client.get("/v1/admin/overview", headers=admin_headers)
        assert admin_overview.status_code == 200
        assert admin_overview.json()["counts"]["users"] == 3

        forbidden = client.get("/v1/admin/overview", headers=alice_headers)
        assert forbidden.status_code == 403

        conv_resp = client.post(
            "/v1/conversations",
            json={"recipient_username": "bob@example.com"},
            headers=alice_headers,
        )
        assert conv_resp.status_code == 200, conv_resp.text
        conversation_id = conv_resp.json()["conversation_id"]

        send_resp = client.post(
            "/v1/messages",
            json={
                "recipient_username": "bob@example.com",
                "content": "hello secret",
            },
            headers=alice_headers,
        )
        assert send_resp.status_code == 200, send_resp.text

        fetch_resp = client.get(
            "/v1/messages",
            params={"with": "bob@example.com"},
            headers=alice_headers,
        )
        assert fetch_resp.status_code == 200
        assert fetch_resp.json()[0]["content"] == "hello secret"

        target = next(
            user
            for user in admin_overview.json()["users"]
            if user["username"] == "bob@example.com"
        )
        disabled = client.patch(
            f"/v1/admin/users/{target['id']}",
            json={"is_active": False},
            headers=admin_headers,
        )
        assert disabled.status_code == 200
        assert client.post(
            "/v1/login",
            json={
                "username": "bob@example.com",
                "password": "StrongPass456!abc",
            },
        ).status_code == 403

        cannot_disable_self = client.patch(
            f"/v1/admin/users/{admin_login.json()['user']['id']}",
            json={"is_active": False},
            headers=admin_headers,
        )
        assert cannot_disable_self.status_code == 400

        unauthorized = client.get(
            "/v1/messages",
            params={"with": "bob@example.com"},
        )
        assert unauthorized.status_code == 401

        logout = client.post("/v1/logout", headers=alice_headers)
        assert logout.status_code == 200
        revoked = client.get("/v1/me", headers=alice_headers)
        assert revoked.status_code == 401

        conn = main.get_db_connection()
        try:
            row = conn.execute(
                "SELECT content FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT 1",
                (conversation_id,),
            ).fetchone()
            assert row is not None
            assert row["content"] != "hello secret"
            assert "hello secret" not in row["content"]
        finally:
            conn.close()


def test_registration_rejects_weak_password_and_non_email(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    with TestClient(main.app) as client:
        short_password = client.post(
            "/v1/register",
            json={"username": "user@example.com", "password": "shortpass"},
        )
        assert short_password.status_code == 422

        invalid_email = client.post(
            "/v1/register",
            json={"username": "not-an-email", "password": "LongEnoughPassword!"},
        )
        assert invalid_email.status_code == 400
