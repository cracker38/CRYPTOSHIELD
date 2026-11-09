import hashlib
import sqlite3

from fastapi.testclient import TestClient

from backend import main


def expected_option_id(challenge_response):
    challenge = challenge_response.json()
    token = challenge["challenge_token"]
    conn = main.get_db_connection()
    try:
        row = conn.execute(
            "SELECT answer_hash FROM onboarding_challenges WHERE token_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
    finally:
        conn.close()
    assert row is not None
    return next(
        option["id"]
        for option in challenge["challenge"]["options"]
        if hashlib.sha256(f"{token}:{option['id']}".encode()).hexdigest()
        == row["answer_hash"]
    )


def complete_challenge(client, challenge_response):
    return client.post(
        "/v1/onboarding/answer",
        json={
            "challenge_token": challenge_response.json()["challenge_token"],
            "option_id": expected_option_id(challenge_response),
        },
    )


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
        admin_headers = {"Authorization": f"Bearer {admin_login.json()['token']}"}

        reg_alice = client.post(
            "/v1/register",
            json={"username": "alice@example.com", "password": "StrongPass123!abc"},
        )
        reg_bob = client.post(
            "/v1/register",
            json={"username": "bob@example.com", "password": "StrongPass456!abc"},
        )
        assert reg_alice.status_code == 200
        assert reg_bob.status_code == 200
        assert reg_alice.json()["status"] == "pending_review"
        assert client.post(
            "/v1/login",
            json={"username": "alice@example.com", "password": "StrongPass123!abc"},
        ).status_code == 403

        admin_overview = client.get("/v1/admin/overview", headers=admin_headers)
        assert admin_overview.status_code == 200
        assert admin_overview.json()["counts"]["users"] == 3
        applicants = {
            user["username"]: user for user in admin_overview.json()["users"]
        }
        assert applicants["alice@example.com"]["account_status"] == "pending_review"
        for username in ("alice@example.com", "bob@example.com"):
            review = client.post(
                f"/v1/admin/users/{applicants[username]['id']}/review",
                json={"decision": "approve"},
                headers=admin_headers,
            )
            assert review.status_code == 200
            assert review.json()["account_status"] == "challenge_required"

        login_alice = client.post(
            "/v1/login",
            json={"username": "alice@example.com", "password": "StrongPass123!abc"},
        )
        assert login_alice.json()["status"] == "challenge_required"
        completed_alice = complete_challenge(client, login_alice)
        assert completed_alice.status_code == 200
        alice_headers = {"Authorization": f"Bearer {completed_alice.json()['token']}"}

        login_bob = client.post(
            "/v1/login",
            json={"username": "bob@example.com", "password": "StrongPass456!abc"},
        )
        completed_bob = complete_challenge(client, login_bob)
        assert completed_bob.status_code == 200

        assert client.get("/v1/admin/overview", headers=alice_headers).status_code == 403
        conv_resp = client.post(
            "/v1/conversations",
            json={"recipient_username": "bob@example.com"},
            headers=alice_headers,
        )
        assert conv_resp.status_code == 200
        conversation_id = conv_resp.json()["conversation_id"]
        send_resp = client.post(
            "/v1/messages",
            json={"recipient_username": "bob@example.com", "content": "hello secret"},
            headers=alice_headers,
        )
        assert send_resp.status_code == 200
        fetch_resp = client.get(
            "/v1/messages",
            params={"with": "bob@example.com"},
            headers=alice_headers,
        )
        assert fetch_resp.status_code == 200
        assert fetch_resp.json()[0]["content"] == "hello secret"

        disabled = client.patch(
            f"/v1/admin/users/{applicants['bob@example.com']['id']}",
            json={"is_active": False},
            headers=admin_headers,
        )
        assert disabled.status_code == 200
        assert client.post(
            "/v1/login",
            json={"username": "bob@example.com", "password": "StrongPass456!abc"},
        ).status_code == 403
        assert client.get(
            "/v1/admin/overview",
            headers={"Authorization": f"Bearer {completed_bob.json()['token']}"},
        ).status_code == 401
        assert client.patch(
            f"/v1/admin/users/{admin_login.json()['user']['id']}",
            json={"is_active": False},
            headers=admin_headers,
        ).status_code == 400
        assert client.get("/v1/messages", params={"with": "bob@example.com"}).status_code == 401

        assert client.post("/v1/logout", headers=alice_headers).status_code == 200
        assert client.get("/v1/me", headers=alice_headers).status_code == 401
        conn = main.get_db_connection()
        try:
            row = conn.execute(
                "SELECT content FROM messages WHERE conversation_id = ? ORDER BY id DESC LIMIT 1",
                (conversation_id,),
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row["content"] != "hello secret"
        assert "hello secret" not in row["content"]


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


def test_approval_challenge_rejects_wrong_answers_and_is_single_use(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "VeryStrongAdminPass123!")

    with TestClient(main.app) as client:
        admin_login = client.post(
            "/v1/login",
            json={
                "username": "admin@example.com",
                "password": "VeryStrongAdminPass123!",
            },
        )
        admin_headers = {"Authorization": f"Bearer {admin_login.json()['token']}"}

        registration = client.post(
            "/v1/register",
            json={"username": "candidate@example.com", "password": "StrongPassword123!"},
        )
        user_id = registration.json()["user"]["id"]
        rejected_registration = client.post(
            "/v1/register",
            json={"username": "rejected@example.com", "password": "StrongPassword456!"},
        )
        rejected_user_id = rejected_registration.json()["user"]["id"]
        rejected = client.post(
            f"/v1/admin/users/{rejected_user_id}/review",
            json={"decision": "reject"},
            headers=admin_headers,
        )
        assert rejected.status_code == 200
        assert rejected.json()["account_status"] == "rejected"
        assert client.post(
            "/v1/login",
            json={"username": "rejected@example.com", "password": "StrongPassword456!"},
        ).status_code == 403

        assert client.post(
            f"/v1/admin/users/{user_id}/review",
            json={"decision": "approve"},
        ).status_code == 401
        assert client.post(
            f"/v1/admin/users/{user_id}/review",
            json={"decision": "approve"},
            headers=admin_headers,
        ).status_code == 200
        assert client.patch(
            f"/v1/admin/users/{user_id}",
            json={"is_active": False},
            headers=admin_headers,
        ).status_code == 409

        challenge_response = client.post(
            "/v1/login",
            json={"username": "candidate@example.com", "password": "StrongPassword123!"},
        )
        details = challenge_response.json()["challenge"]
        token = challenge_response.json()["challenge_token"]
        assert challenge_response.json()["status"] == "challenge_required"
        assert "answer" not in details
        correct_option_id = expected_option_id(challenge_response)
        wrong_option_id = next(
            option["id"]
            for option in details["options"]
            if option["id"] != correct_option_id
        )
        assert client.post(
            "/v1/onboarding/answer",
            json={"challenge_token": token, "option_id": wrong_option_id},
        ).status_code == 400
        assert client.get(
            "/v1/me",
            headers={"Authorization": f"Bearer {token}"},
        ).status_code == 401

        refreshed_challenge = client.post(
            "/v1/login",
            json={"username": "candidate@example.com", "password": "StrongPassword123!"},
        )
        assert [
            option["id"] for option in refreshed_challenge.json()["challenge"]["options"]
        ] != [option["id"] for option in details["options"]]
        assert client.post(
            "/v1/onboarding/answer",
            json={"challenge_token": token, "option_id": correct_option_id},
        ).status_code == 401

        completed = complete_challenge(client, refreshed_challenge)
        assert completed.status_code == 200
        assert client.get(
            "/v1/me",
            headers={"Authorization": f"Bearer {completed.json()['token']}"},
        ).status_code == 200
        assert client.post(
            "/v1/onboarding/answer",
            json={
                "challenge_token": refreshed_challenge.json()["challenge_token"],
                "option_id": expected_option_id(refreshed_challenge),
            },
        ).status_code == 401


def test_onboarding_attempts_are_limited_across_new_challenges(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "VeryStrongAdminPass123!")

    with TestClient(main.app) as client:
        admin_login = client.post(
            "/v1/login",
            json={
                "username": "admin@example.com",
                "password": "VeryStrongAdminPass123!",
            },
        )
        admin_headers = {"Authorization": f"Bearer {admin_login.json()['token']}"}
        registration = client.post(
            "/v1/register",
            json={"username": "candidate@example.com", "password": "StrongPassword123!"},
        )
        user_id = registration.json()["user"]["id"]
        assert client.post(
            f"/v1/admin/users/{user_id}/review",
            json={"decision": "approve"},
            headers=admin_headers,
        ).status_code == 200

        for attempt in range(main.CHALLENGE_ATTEMPT_LIMIT):
            challenge_response = client.post(
                "/v1/login",
                json={"username": "candidate@example.com", "password": "StrongPassword123!"},
            )
            token = challenge_response.json()["challenge_token"]
            options = challenge_response.json()["challenge"]["options"]
            correct_option_id = expected_option_id(challenge_response)
            wrong_option_id = next(
                option["id"] for option in options if option["id"] != correct_option_id
            )
            response = client.post(
                "/v1/onboarding/answer",
                json={"challenge_token": token, "option_id": wrong_option_id},
            )
            expected_status = 429 if attempt == main.CHALLENGE_ATTEMPT_LIMIT - 1 else 400
            assert response.status_code == expected_status

        limited_login = client.post(
            "/v1/login",
            json={"username": "candidate@example.com", "password": "StrongPassword123!"},
        )
        assert limited_login.status_code == 429


def test_legacy_user_schema_migrates_account_statuses(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.db"
    monkeypatch.setattr(main, "DATABASE_PATH", str(database_path))
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)

    conn = sqlite3.connect(database_path)
    try:
        conn.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                encryption_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO users
                (username, password_hash, password_salt, encryption_key, created_at, is_active)
            VALUES (?, 'hash', 'salt', 'key', '2026-01-01T00:00:00+00:00', ?)
            """,
            [
                ("active@example.com", 1),
                ("disabled@example.com", 0),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    main.initialize_db()
    assert main.get_user_by_username("active@example.com")["account_status"] == "active"
    assert main.get_user_by_username("disabled@example.com")["account_status"] == "disabled"
