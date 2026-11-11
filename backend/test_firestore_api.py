from datetime import timedelta

from backend.firestore_api import (
    ACTION_RATE_WINDOW,
    CHALLENGE_ATTEMPT_WINDOW,
    LOGIN_EMAIL_LIMIT,
    LOGIN_IP_LIMIT,
    _challenge_attempt_state,
    email_id,
    enforce_auth_rate_limit,
    hash_password,
    make_challenge,
    utcnow,
    verify_password,
)


def test_password_hash_uses_a_unique_salt_and_verifies_password():
    first = hash_password("a-long-password")
    second = hash_password("a-long-password")

    assert first != second
    assert verify_password("a-long-password", first)
    assert not verify_password("a-different-password", first)


def test_email_index_is_case_insensitive_and_challenge_options_are_unique():
    assert email_id("User@example.com") == email_id(" user@example.com ")

    question, options, correct_id = make_challenge()

    assert question
    assert len(options) == 4
    assert len({option["id"] for option in options}) == 4
    assert correct_id in {option["id"] for option in options}
    assert all(option["text"] for option in options)


def test_expired_onboarding_cooldown_persists_attempt_reset():
    now = utcnow()
    user = {
        "challengeAttempts": 5,
        "challengeWindowStartedAt": now - CHALLENGE_ATTEMPT_WINDOW,
    }

    attempts, window_start, updates = _challenge_attempt_state(user, now)

    assert attempts == 0
    assert window_start is None
    assert updates == {"challengeAttempts": 0}


def test_active_onboarding_cooldown_preserves_attempt_state():
    now = utcnow()
    window_start = now - timedelta(minutes=5)
    user = {"challengeAttempts": 2, "challengeWindowStartedAt": window_start}

    attempts, actual_window_start, updates = _challenge_attempt_state(user, now)

    assert attempts == 2
    assert actual_window_start == window_start
    assert updates == {}


def test_login_rate_limits_are_shared_and_do_not_store_raw_email(monkeypatch):
    from types import SimpleNamespace

    import backend.firestore_api as api

    calls = []
    monkeypatch.setattr(
        api,
        "enforce_rate_limit",
        lambda *args: calls.append(args),
    )
    request = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.12"),
    )

    enforce_auth_rate_limit(
        request,
        "PERSON@example.com",
        ip_limit=LOGIN_IP_LIMIT,
        email_limit=LOGIN_EMAIL_LIMIT,
    )

    assert len(calls) == 3
    assert calls[0] == ("auth-ip", "203.0.113.12", LOGIN_IP_LIMIT, api.AUTH_RATE_WINDOW)
    assert calls[1][0] == "auth-email"
    assert calls[1][1] == email_id("person@example.com")
    assert "PERSON@example.com" not in repr(calls)
    assert calls[2][0] == "auth-email-ip"
    assert calls[2][3] == api.AUTH_RATE_WINDOW


def test_email_delivery_uses_starttls_and_includes_action_token(monkeypatch):
    import backend.firestore_api as api

    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port, timeout))

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def ehlo(self):
            calls.append(("ehlo",))

        def starttls(self, context):
            calls.append(("starttls", context))

        def login(self, username, password):
            calls.append(("login", username, password))

        def send_message(self, message):
            calls.append(("send", message["To"], message.get_content()))

    monkeypatch.setenv("SMTP_HOST", "mail.example.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_FROM", "noreply@example.test")
    monkeypatch.setenv("SMTP_USERNAME", "mailer")
    monkeypatch.setenv("SMTP_PASSWORD", "test-password")
    monkeypatch.setattr(api.smtplib, "SMTP", FakeSMTP)

    api.send_action_email(
        "user@example.test",
        "Verify account",
        "one-time-code",
        "email verification",
    )

    assert calls[0] == ("connect", "mail.example.test", 587, 10)
    assert sum(call[0] == "starttls" for call in calls) == 1
    assert calls[-1][0] == "send"
    assert "one-time-code" in calls[-1][2]
