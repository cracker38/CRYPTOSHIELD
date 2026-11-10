from datetime import timedelta

from backend.firestore_api import (
    CHALLENGE_ATTEMPT_WINDOW,
    _challenge_attempt_state,
    email_id,
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
