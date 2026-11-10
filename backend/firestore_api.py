from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from firebase_admin import firestore, initialize_app
from google.api_core.exceptions import AlreadyExists
from pydantic import BaseModel, Field

SESSION_TTL = timedelta(days=30)
CHALLENGE_TTL = timedelta(minutes=10)
CHALLENGE_ATTEMPT_LIMIT = 5
CHALLENGE_ATTEMPT_WINDOW = timedelta(minutes=15)
PASSWORD_ITERATIONS = 310_000
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

SCENARIOS = (
    (
        "A teammate reports an unexpected multi-factor authentication prompt. What is the safest first response?",
        (
            "Deny the prompt and report it through the approved security channel.",
            "Approve it once to stop the notifications.",
            "Share the prompt details with a coworker in a public chat.",
            "Ignore it and continue using the account.",
        ),
    ),
    (
        "A browser warns that an internal service certificate is invalid. What should you do?",
        (
            "Stop and report the issue; do not bypass the certificate warning.",
            "Disable certificate checks for the session.",
            "Continue if the page looks familiar.",
            "Copy the warning into a public forum with the service URL.",
        ),
    ),
    (
        "You receive an unexpected attachment asking you to review an urgent invoice. What is the safest action?",
        (
            "Do not open it; report it using the organization's phishing process.",
            "Open it in your normal account to identify the sender.",
            "Forward it to teammates to ask whether it is legitimate.",
            "Reply to the sender requesting proof of identity.",
        ),
    ),
    (
        "A production device may be compromised. What should you prioritize?",
        (
            "Follow the incident-response plan, limit exposure, and preserve evidence.",
            "Delete files that look suspicious before notifying anyone.",
            "Post system details in an unrestricted chat for quick help.",
            "Reinstall immediately without recording what happened.",
        ),
    ),
    (
        "A colleague asks for administrator access to complete a short task. What is the best practice?",
        (
            "Grant only the minimum required access for the shortest necessary time.",
            "Share your own administrator credentials.",
            "Grant permanent administrator access to avoid future delays.",
            "Disable access controls until the task is complete.",
        ),
    ),
    (
        "A backup job reports success. What best demonstrates that recovery is dependable?",
        (
            "Perform controlled restore tests and verify data integrity.",
            "Assume the job worked because it returned a success message.",
            "Keep the only backup on the same device as the source.",
            "Wait until an incident to find out whether restoration works.",
        ),
    ),
    (
        "You suspect your password was exposed. What is the safest response?",
        (
            "Report it and change it through the trusted account recovery path.",
            "Reuse it with a small change on all work systems.",
            "Send it to the security team in ordinary email.",
            "Wait to see whether an account alert arrives.",
        ),
    ),
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: str | None = None) -> str:
    actual_salt = salt or secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), actual_salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    )
    return f"{actual_salt}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    actual = hash_password(password, salt).split("$", 1)[1]
    return secrets.compare_digest(actual, expected)


def email_id(email: str) -> str:
    return digest(email.strip().lower())


def make_challenge() -> tuple[str, list[dict[str, str]], str]:
    question, answers = secrets.choice(SCENARIOS)
    options = [{"id": secrets.token_urlsafe(9), "text": text} for text in answers]
    secrets.SystemRandom().shuffle(options)
    correct = next(option["id"] for option in options if option["text"] == answers[0])
    return question, options, correct


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} must be configured.")
    return value


def _firestore_client():
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("FIREBASE_PROJECT_ID")
    if not project_id:
        raise RuntimeError("Set GOOGLE_CLOUD_PROJECT to the Firebase project ID.")
    try:
        from firebase_admin import get_app

        get_app()
    except ValueError:
        initialize_app(options={"projectId": project_id})
    return firestore.client()


app = FastAPI(
    title="CRYPTOSHIELD API",
    version="1.0.0",
    description="Self-hosted API with Firebase Firestore as its data store.",
)

origins = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5000"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

db = None
message_cipher = None


@app.on_event("startup")
def startup() -> None:
    global db, message_cipher
    db = _firestore_client()
    key = _required_env("MESSAGE_ENCRYPTION_KEY")
    try:
        message_cipher = Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise RuntimeError(
            "MESSAGE_ENCRYPTION_KEY must be a valid Fernet key."
        ) from error
    bootstrap_admin()


def database():
    if db is None:
        raise HTTPException(status_code=503, detail="Firestore is not initialized.")
    return db


def record_event(
    subject_id: str, event_type: str, actor_id: str | None = None
) -> None:
    database().collection("accountAuditLog").add(
        {
            "actorUid": actor_id,
            "subjectUid": subject_id,
            "eventType": event_type,
            "createdAt": utcnow(),
        }
    )


def _user_summary(user_id: str, user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user_id,
        "username": user["email"],
        "role": user.get("role", "user"),
        "account_status": user.get("accountStatus", "active"),
        "is_active": user.get("isActive", True),
    }


def bootstrap_admin() -> None:
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email and not password:
        raise RuntimeError("Set ADMIN_EMAIL and ADMIN_PASSWORD for initial administrator access.")
    if not email or not password:
        raise RuntimeError("Set both ADMIN_EMAIL and ADMIN_PASSWORD or neither.")
    if not EMAIL_PATTERN.fullmatch(email) or len(password) < 12:
        raise RuntimeError("ADMIN_EMAIL must be valid and ADMIN_PASSWORD at least 12 characters.")

    client = database()
    email_ref = client.collection("userEmails").document(email_id(email))
    user_id = secrets.token_urlsafe(18)
    user_ref = client.collection("users").document(user_id)

    @firestore.transactional
    def create_admin(transaction):
        existing_email = email_ref.get(transaction=transaction)
        if existing_email.exists:
            existing_user_ref = client.collection("users").document(
                existing_email.get("uid")
            )
            existing_user = existing_user_ref.get(transaction=transaction)
            if existing_user.exists and existing_user.get("role") == "admin":
                return
            raise RuntimeError(
                "ADMIN_EMAIL already belongs to a non-admin account; promote it using a trusted operator procedure."
            )
        now = utcnow()
        transaction.create(
            user_ref,
            {
                "email": email,
                "emailLower": email,
                "passwordHash": hash_password(password),
                "role": "admin",
                "accountStatus": "active",
                "isActive": True,
                "createdAt": now,
            },
        )
        transaction.create(email_ref, {"uid": user_id})

    create_admin(client.transaction())


def current_user(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")
    client = database()
    session_ref = client.collection("sessions").document(digest(token))
    session = session_ref.get()
    if not session.exists:
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    session_data = session.to_dict() or {}
    expires_at = session_data.get("expiresAt")
    if not expires_at or expires_at <= utcnow():
        session_ref.delete()
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    user_ref = client.collection("users").document(session_data["uid"])
    user_doc = user_ref.get()
    user = user_doc.to_dict() if user_doc.exists else None
    if (
        user is None
        or user.get("accountStatus") != "active"
        or user.get("isActive") is not True
    ):
        session_ref.delete()
        raise HTTPException(status_code=403, detail="This account is not active.")
    return {"uid": user_doc.id, **user}


def require_admin(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return user


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    database().collection("sessions").document(digest(token)).set(
        {"uid": user_id, "createdAt": utcnow(), "expiresAt": utcnow() + SESSION_TTL}
    )
    return token


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class OnboardingAnswerRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=128)
    option_id: str = Field(min_length=8, max_length=64)


class AdminReviewRequest(BaseModel):
    decision: Literal["approve", "reject"]


class UserStatusRequest(BaseModel):
    is_active: bool


class SendMessageRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=254)
    content: str = Field(min_length=1, max_length=5000)


class ToolHistoryRequest(BaseModel):
    kind: Literal["analysis", "lab"]
    input: str = Field(min_length=1, max_length=20000)
    result: str = Field(min_length=1, max_length=20000)


@app.get("/health")
def health() -> dict[str, str]:
    client = database()
    list(client.collection("_health").limit(1).stream())
    return {"status": "ok", "service": "cryptoshield-api"}


@app.post("/v1/register")
def register_user(payload: RegisterRequest) -> dict[str, Any]:
    email = payload.username.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    client = database()
    email_ref = client.collection("userEmails").document(email_id(email))
    user_id = secrets.token_urlsafe(18)
    user_ref = client.collection("users").document(user_id)

    @firestore.transactional
    def create_user(transaction):
        if email_ref.get(transaction=transaction).exists:
            return False
        now = utcnow()
        transaction.create(
            user_ref,
            {
                "email": email,
                "emailLower": email,
                "passwordHash": hash_password(payload.password),
                "role": "user",
                "accountStatus": "pending_review",
                "isActive": False,
                "createdAt": now,
            },
        )
        transaction.create(email_ref, {"uid": user_id})
        return True

    if not create_user(client.transaction()):
        raise HTTPException(status_code=409, detail="This email is already registered.")
    record_event(user_id, "registration_submitted")
    return {
        "status": "pending_review",
        "user": {"id": user_id, "username": email, "role": "user"},
        "message": "Registration submitted. An administrator must review your request.",
    }


def issue_challenge(user_id: str) -> dict[str, Any]:
    client = database()
    user_ref = client.collection("users").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="User was not found.")
    user = user_doc.to_dict() or {}
    if user.get("accountStatus") != "challenge_required":
        raise HTTPException(status_code=403, detail="This account is not awaiting onboarding.")
    now = utcnow()
    window_start = user.get("challengeWindowStartedAt")
    attempts = int(user.get("challengeAttempts", 0))
    if window_start and now - window_start >= CHALLENGE_ATTEMPT_WINDOW:
        attempts, window_start = 0, None
    if attempts >= CHALLENGE_ATTEMPT_LIMIT:
        raise HTTPException(
            status_code=429,
            detail="Challenge attempts are temporarily limited. Try again later.",
        )

    token = secrets.token_urlsafe(32)
    question, options, correct_id = make_challenge()
    challenge_id = digest(token)
    client.collection("onboardingChallenges").document(challenge_id).create(
        {
            "uid": user_id,
            "question": question,
            "options": options,
            "answerHash": digest(f"{token}:{correct_id}"),
            "createdAt": now,
            "expiresAt": now + CHALLENGE_TTL,
            "consumed": False,
        }
    )
    updates = {}
    if not window_start:
        updates["challengeWindowStartedAt"] = now
    if updates:
        user_ref.update(updates)
    record_event(user_id, "challenge_issued")
    return {
        "challenge_token": token,
        "challenge": {
            "question": question,
            "options": options,
            "expires_at": (now + CHALLENGE_TTL).isoformat(),
        },
    }


@app.post("/v1/login")
def login_user(payload: LoginRequest) -> dict[str, Any]:
    email = payload.username.strip().lower()
    client = database()
    email_doc = client.collection("userEmails").document(email_id(email)).get()
    if not email_doc.exists:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    user_ref = client.collection("users").document(email_doc.get("uid"))
    user_doc = user_ref.get()
    user = user_doc.to_dict() if user_doc.exists else None
    if user is None or not verify_password(payload.password, user.get("passwordHash", "")):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    status = user.get("accountStatus")
    if status == "pending_review":
        raise HTTPException(status_code=403, detail="Your account request is awaiting administrator review.")
    if status == "rejected":
        raise HTTPException(status_code=403, detail="Your account request was not approved.")
    if status == "challenge_required":
        return {"status": "challenge_required", **issue_challenge(user_doc.id)}
    if status == "disabled" or user.get("isActive") is not True:
        raise HTTPException(status_code=403, detail="This account has been disabled.")
    token = create_session(user_doc.id)
    return {
        "status": "logged_in",
        "token": token,
        "user": {"id": user_doc.id, "username": email, "role": user.get("role", "user")},
    }


@app.post("/v1/onboarding/answer")
def answer_onboarding(payload: OnboardingAnswerRequest) -> dict[str, Any]:
    client = database()
    token_hash = digest(payload.challenge_token)
    challenge_ref = client.collection("onboardingChallenges").document(token_hash)
    token = secrets.token_urlsafe(32)
    session_ref = client.collection("sessions").document(digest(token))

    @firestore.transactional
    def consume_challenge(transaction):
        challenge_doc = challenge_ref.get(transaction=transaction)
        if not challenge_doc.exists:
            return {"error": 401, "detail": "Challenge is invalid or has already been used."}
        challenge = challenge_doc.to_dict() or {}
        user_ref = client.collection("users").document(challenge["uid"])
        user_doc = user_ref.get(transaction=transaction)
        user = user_doc.to_dict() if user_doc.exists else None
        if user is None or user.get("accountStatus") != "challenge_required":
            return {"error": 409, "detail": "This account is no longer awaiting onboarding."}
        now = utcnow()
        if challenge.get("consumed") or challenge.get("expiresAt") <= now:
            transaction.update(challenge_ref, {"consumed": True})
            return {"error": 410, "detail": "Challenge expired. Sign in to request a new one."}
        window_start = user.get("challengeWindowStartedAt")
        attempts = int(user.get("challengeAttempts", 0))
        if window_start and now - window_start >= CHALLENGE_ATTEMPT_WINDOW:
            attempts, window_start = 0, None
        if attempts >= CHALLENGE_ATTEMPT_LIMIT:
            return {"error": 429, "detail": "Challenge attempts are temporarily limited. Try again later."}
        option_ids = {option["id"] for option in challenge["options"]}
        correct = secrets.compare_digest(
            digest(f"{payload.challenge_token}:{payload.option_id}"),
            challenge["answerHash"],
        )
        if payload.option_id not in option_ids or not correct:
            attempts += 1
            transaction.update(
                user_ref,
                {
                    "challengeAttempts": attempts,
                    "challengeWindowStartedAt": window_start or now,
                },
            )
            transaction.update(
                challenge_ref,
                {
                    "attempts": firestore.Increment(1),
                    "consumed": attempts >= CHALLENGE_ATTEMPT_LIMIT,
                },
            )
            return {
                "error": 429 if attempts >= CHALLENGE_ATTEMPT_LIMIT else 400,
                "detail": (
                    "Challenge attempt limit reached. Try again after the temporary cooldown."
                    if attempts >= CHALLENGE_ATTEMPT_LIMIT
                    else "That answer is incorrect. Try again."
                ),
                "uid": user_doc.id,
            }

        transaction.update(challenge_ref, {"consumed": True})
        transaction.update(
            user_ref,
            {
                "accountStatus": "active",
                "isActive": True,
                "challengeAttempts": 0,
                "challengeWindowStartedAt": firestore.DELETE_FIELD,
            },
        )
        transaction.create(
            session_ref,
            {"uid": user_doc.id, "createdAt": now, "expiresAt": now + SESSION_TTL},
        )
        return {"uid": user_doc.id, "email": user["email"], "role": user.get("role", "user")}

    result = consume_challenge(client.transaction())
    if "error" in result:
        if result["error"] in (400, 429) and result.get("uid"):
            record_event(result["uid"], "challenge_failed")
        raise HTTPException(status_code=result["error"], detail=result["detail"])
    record_event(result["uid"], "challenge_passed")
    return {
        "status": "logged_in",
        "token": token,
        "user": {
            "id": result["uid"],
            "username": result["email"],
            "role": result["role"],
        },
    }


@app.get("/v1/me")
def get_me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return _user_summary(user["uid"], user)


@app.post("/v1/logout")
def logout(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")
    database().collection("sessions").document(
        digest(authorization.removeprefix("Bearer ").strip())
    ).delete()
    return {"status": "logged_out"}


@app.get("/v1/admin/overview")
def admin_overview(admin: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    client = database()
    users = list(client.collection("users").stream())
    conversations = list(client.collection("conversations").stream())
    message_count = sum(
        len(list(conversation.reference.collection("messages").stream()))
        for conversation in conversations
    )
    return {
        "counts": {
            "users": len(users),
            "active_users": sum(bool(doc.get("isActive")) for doc in users),
            "conversations": len(conversations),
            "messages": message_count,
        },
        "users": [
            {
                "id": doc.id,
                "username": doc.get("email", ""),
                "role": doc.get("role", "user"),
                "is_active": doc.get("isActive", False),
                "account_status": doc.get("accountStatus", "pending_review"),
                "created_at": _iso(doc.get("createdAt")),
            }
            for doc in sorted(users, key=lambda item: item.get("createdAt") or utcnow(), reverse=True)
        ],
    }


def _iso(value: Any) -> str:
    return value.isoformat() if hasattr(value, "isoformat") else ""


@app.post("/v1/admin/users/{user_id}/review")
def review_user(
    user_id: str,
    payload: AdminReviewRequest,
    admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    user_ref = database().collection("users").document(user_id)
    user_doc = user_ref.get()
    if not user_doc.exists:
        raise HTTPException(status_code=404, detail="User was not found.")
    user = user_doc.to_dict() or {}
    if user.get("role") == "admin":
        raise HTTPException(status_code=400, detail="Administrator accounts cannot use applicant review.")
    status = user.get("accountStatus")
    allowed = {"pending_review"} if payload.decision == "approve" else {"pending_review", "challenge_required"}
    if status not in allowed:
        raise HTTPException(status_code=409, detail="This account cannot be changed through applicant review.")
    next_status = "challenge_required" if payload.decision == "approve" else "rejected"
    user_ref.update({"accountStatus": next_status, "isActive": False})
    _revoke_user_sessions(user_id)
    record_event(
        user_id,
        "registration_approved" if payload.decision == "approve" and status == "pending_review"
        else "registration_rejected" if payload.decision == "reject" and status == "pending_review"
        else "approval_revoked",
        admin["uid"],
    )
    return {"id": user_id, "username": user["email"], "account_status": next_status}


def _revoke_user_sessions(user_id: str) -> None:
    client = database()
    batch = client.batch()
    for session in client.collection("sessions").where("uid", "==", user_id).stream():
        batch.delete(session.reference)
    batch.commit()


@app.patch("/v1/admin/users/{user_id}")
def set_user_status(
    user_id: str,
    payload: UserStatusRequest,
    admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    client = database()
    target_ref = client.collection("users").document(user_id)
    target_doc = target_ref.get()
    if not target_doc.exists:
        raise HTTPException(status_code=404, detail="User was not found.")
    target = target_doc.to_dict() or {}
    status = target.get("accountStatus")
    if payload.is_active and status not in {"disabled", "active"}:
        raise HTTPException(status_code=409, detail="Pending or rejected accounts must complete administrator review and onboarding.")
    if not payload.is_active and status not in {"active", "disabled"}:
        raise HTTPException(status_code=409, detail="This account cannot be disabled in its current state.")
    if user_id == admin["uid"] and not payload.is_active:
        raise HTTPException(status_code=400, detail="You cannot disable your own account.")
    if target.get("role") == "admin" and not payload.is_active:
        active_admins = sum(
            1 for doc in client.collection("users").where("role", "==", "admin").stream()
            if doc.get("isActive") is True
        )
        if active_admins <= 1:
            raise HTTPException(status_code=400, detail="The last active administrator cannot be disabled.")
    next_status = "active" if payload.is_active else "disabled"
    target_ref.update({"isActive": payload.is_active, "accountStatus": next_status})
    if not payload.is_active:
        _revoke_user_sessions(user_id)
    if status != next_status:
        record_event(user_id, "account_enabled" if payload.is_active else "account_disabled", admin["uid"])
    return {
        "id": user_id,
        "username": target["email"],
        "is_active": payload.is_active,
        "account_status": next_status,
    }


def conversation_id(first_uid: str, second_uid: str) -> str:
    return digest(":".join(sorted((first_uid, second_uid))))


def get_conversation(user: dict[str, Any], recipient_email: str):
    client = database()
    recipient_index = client.collection("userEmails").document(email_id(recipient_email))
    recipient_index_doc = recipient_index.get()
    if not recipient_index_doc.exists:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")
    recipient_id = recipient_index_doc.get("uid")
    if recipient_id == user["uid"]:
        raise HTTPException(status_code=400, detail="You cannot start a conversation with yourself.")
    recipient_doc = client.collection("users").document(recipient_id).get()
    recipient = recipient_doc.to_dict() if recipient_doc.exists else None
    if not recipient or recipient.get("accountStatus") != "active" or recipient.get("isActive") is not True:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")
    cid = conversation_id(user["uid"], recipient_id)
    conversation_ref = client.collection("conversations").document(cid)
    if not conversation_ref.get().exists:
        key = Fernet.generate_key()
        encrypted_key = message_cipher.encrypt(key).decode("ascii")
        participants = sorted([user["uid"], recipient_id])
        try:
            conversation_ref.create(
                {
                    "participants": participants,
                    "participantEmails": {
                        user["uid"]: user["email"],
                        recipient_id: recipient["email"],
                    },
                    "encryptedKey": encrypted_key,
                    "createdAt": utcnow(),
                }
            )
        except AlreadyExists:
            pass
    return cid, recipient_id, recipient, conversation_ref


@app.post("/v1/conversations")
def create_conversation(
    payload: dict[str, str],
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    email = payload.get("recipient_username", "").strip().lower()
    cid, recipient_id, recipient, _ = get_conversation(user, email)
    return {
        "conversation_id": cid,
        "participant": {"id": user["uid"], "username": user["email"]},
        "recipient": {"id": recipient_id, "username": recipient["email"]},
        "encrypted": True,
    }


@app.post("/v1/messages")
def send_message(
    payload: SendMessageRequest,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    cid, recipient_id, recipient, conversation_ref = get_conversation(
        user, payload.recipient_username.strip().lower()
    )
    conversation = conversation_ref.get().to_dict() or {}
    key = message_cipher.decrypt(conversation["encryptedKey"].encode("ascii"))
    ciphertext = Fernet(key).encrypt(payload.content.strip().encode("utf-8")).decode("ascii")
    created = utcnow()
    conversation_ref.collection("messages").add(
        {
            "senderId": user["uid"],
            "senderEmail": user["email"],
            "receiverId": recipient_id,
            "content": ciphertext,
            "createdAt": created,
        }
    )
    return {
        "status": "sent",
        "conversation_id": cid,
        "recipient_username": recipient["email"],
        "content": payload.content.strip(),
        "encrypted": True,
        "created_at": created.isoformat(),
    }


@app.get("/v1/messages")
def get_messages(
    with_user: str = Query(..., alias="with"),
    user: dict[str, Any] = Depends(current_user),
) -> list[dict[str, Any]]:
    cid, _, _, conversation_ref = get_conversation(user, with_user.strip().lower())
    conversation = conversation_ref.get().to_dict() or {}
    key = message_cipher.decrypt(conversation["encryptedKey"].encode("ascii"))
    result = []
    for message in conversation_ref.collection("messages").order_by("createdAt").stream():
        data = message.to_dict() or {}
        try:
            content = Fernet(key).decrypt(data["content"].encode("ascii")).decode("utf-8")
        except (ValueError, KeyError) as error:
            raise HTTPException(status_code=500, detail="Stored message could not be decrypted.") from error
        result.append(
            {
                "id": message.id,
                "conversation_id": cid,
                "sender_username": data.get("senderEmail", ""),
                "receiver_username": conversation.get("participantEmails", {}).get(data.get("receiverId"), ""),
                "content": content,
                "created_at": _iso(data.get("createdAt")),
            }
        )
    return result


@app.get("/v1/tool-history")
def get_tool_history(
    kind: Literal["analysis", "lab"],
    user: dict[str, Any] = Depends(current_user),
) -> list[dict[str, Any]]:
    query = (
        database()
        .collection("users")
        .document(user["uid"])
        .collection("toolHistory")
        .where("kind", "==", kind)
        .order_by("createdAt", direction=firestore.Query.DESCENDING)
        .limit(50)
    )
    return [
        {
            "id": record.id,
            "input": record.get("input"),
            "result": record.get("result"),
            "created_at": _iso(record.get("createdAt")),
        }
        for record in query.stream()
    ]


@app.post("/v1/tool-history", status_code=201)
def save_tool_history(
    payload: ToolHistoryRequest,
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, str]:
    ref = (
        database()
        .collection("users")
        .document(user["uid"])
        .collection("toolHistory")
        .document()
    )
    ref.set(
        {
            "kind": payload.kind,
            "input": payload.input,
            "result": payload.result,
            "createdAt": utcnow(),
        }
    )
    return {"id": ref.id, "status": "saved"}
