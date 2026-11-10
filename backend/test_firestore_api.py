from backend.firestore_api import email_id, hash_password, make_challenge, verify_password


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
