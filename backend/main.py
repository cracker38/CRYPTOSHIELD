from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = str(Path(os.environ.get("CRYPTOSHIELD_DATABASE_PATH", BASE_DIR / "cryptoshield.db")))
SESSION_TTL = timedelta(days=30)
DATABASE_VERSION = 2

app = FastAPI(
    title="CRYPTOSHIELD AI API",
    version="0.3.0",
    description="Account and ciphertext-relay APIs. Message encryption and decryption happen on clients.",
)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)
    encryption_public_key: str = Field(min_length=40, max_length=64)
    signing_public_key: str = Field(min_length=40, max_length=64)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)


class CreateConversationRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=32)


class SendMessageRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=32)
    ciphertext: str = Field(min_length=1, max_length=20000)


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize_db() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                encryption_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                encryption_public_key TEXT,
                signing_public_key TEXT
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "encryption_public_key" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN encryption_public_key TEXT")
        if "signing_public_key" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN signing_public_key TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_a_id INTEGER NOT NULL,
                user_b_id INTEGER NOT NULL,
                encryption_key TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_a_id) REFERENCES users(id),
                FOREIGN KEY(user_b_id) REFERENCES users(id),
                UNIQUE(user_a_id, user_b_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id),
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
            """
        )

        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version < DATABASE_VERSION:
            conn.execute("DELETE FROM messages")
            conn.execute("DELETE FROM conversations")
            conn.execute("UPDATE users SET encryption_key = ''")
            conn.execute(f"PRAGMA user_version = {DATABASE_VERSION}")
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return salt, derived.hex()


def verify_password(password: str, stored_value: str) -> bool:
    parts = stored_value.split("$")
    if len(parts) != 2:
        return False
    salt, expected_hash = parts
    _, actual_hash = hash_password(password, salt)
    return secrets.compare_digest(actual_hash, expected_hash)


def validate_public_key(value: str) -> bool:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 32


def get_user_by_username(username: str) -> sqlite3.Row | None:
    conn = get_db_connection()
    try:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username.strip(),)).fetchone()
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    conn = get_db_connection()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = (now + SESSION_TTL).isoformat()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now.isoformat(), expires_at),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def get_current_user(request: Request) -> sqlite3.Row:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token.")

    token = authorization.removeprefix("Bearer ").strip()
    conn = get_db_connection()
    try:
        session = conn.execute(
            """
            SELECT s.token, s.user_id, s.expires_at, u.username, u.created_at,
                   u.encryption_public_key, u.signing_public_key
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    finally:
        conn.close()

    if session is None or datetime.fromisoformat(session["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    return session


def get_or_create_conversation(current_user_id: int, recipient_username: str) -> sqlite3.Row:
    recipient = get_user_by_username(recipient_username)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")
    if recipient["id"] == current_user_id:
        raise HTTPException(status_code=400, detail="A user cannot message themselves.")
    if not recipient["encryption_public_key"] or not recipient["signing_public_key"]:
        raise HTTPException(status_code=409, detail="Recipient must update their app and register device keys.")

    user_a_id, user_b_id = sorted((current_user_id, recipient["id"]))
    conn = get_db_connection()
    try:
        conversation = conn.execute(
            "SELECT * FROM conversations WHERE user_a_id = ? AND user_b_id = ?",
            (user_a_id, user_b_id),
        ).fetchone()
        if conversation is not None:
            return conversation

        created_at = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO conversations (user_a_id, user_b_id, encryption_key, created_at)
            VALUES (?, ?, '', ?)
            """,
            (user_a_id, user_b_id, created_at),
        )
        conn.commit()
        return conn.execute("SELECT * FROM conversations WHERE id = ?", (cursor.lastrowid,)).fetchone()
    finally:
        conn.close()


@app.on_event("startup")
def startup_event() -> None:
    initialize_db()


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "ok", "service": "cryptoshield-api", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/v1/register")
def register_user(payload: RegisterRequest) -> dict[str, object]:
    username = payload.username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", username):
        raise HTTPException(status_code=400, detail="Username may only contain letters, numbers, dots, underscores and hyphens.")
    if not validate_public_key(payload.encryption_public_key) or not validate_public_key(payload.signing_public_key):
        raise HTTPException(status_code=400, detail="Device public keys must be valid 32-byte URL-safe Base64 values.")
    if get_user_by_username(username) is not None:
        raise HTTPException(status_code=409, detail="This username is already registered.")

    salt, password_hash = hash_password(payload.password)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        try:
            cursor = conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, password_salt, encryption_key, created_at,
                     encryption_public_key, signing_public_key)
                VALUES (?, ?, ?, '', ?, ?, ?)
                """,
                (
                    username,
                    f"{salt}${password_hash}",
                    salt,
                    now,
                    payload.encryption_public_key,
                    payload.signing_public_key,
                ),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="This username is already registered.") from exc
    finally:
        conn.close()

    return {"status": "registered", "user": {"id": cursor.lastrowid, "username": username}}


@app.post("/v1/login")
def login_user(payload: LoginRequest) -> dict[str, object]:
    user = get_user_by_username(payload.username)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    if not user["encryption_public_key"] or not user["signing_public_key"]:
        raise HTTPException(status_code=409, detail="This account has no registered device keys. Re-register this prototype account.")
    return {
        "status": "logged_in",
        "token": create_session(int(user["id"])),
        "user": {"id": user["id"], "username": user["username"]},
    }


@app.get("/v1/me")
def get_me(user: sqlite3.Row = Depends(get_current_user)) -> dict[str, object]:
    return {
        "id": user["user_id"],
        "username": user["username"],
        "created_at": user["created_at"],
        "encryption_public_key": user["encryption_public_key"],
        "signing_public_key": user["signing_public_key"],
    }


@app.post("/v1/logout")
def logout_user(user: sqlite3.Row = Depends(get_current_user)) -> dict[str, str]:
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (user["token"],))
        conn.commit()
    finally:
        conn.close()
    return {"status": "logged_out"}


@app.get("/v1/users/{username}/public-key")
def get_public_key(
    username: str,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, str]:
    user = get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User was not found.")
    if not user["encryption_public_key"] or not user["signing_public_key"]:
        raise HTTPException(status_code=409, detail="User has no registered device keys.")
    return {
        "username": user["username"],
        "encryption_public_key": user["encryption_public_key"],
        "signing_public_key": user["signing_public_key"],
    }


@app.post("/v1/conversations")
def create_conversation(
    body: CreateConversationRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, object]:
    conversation = get_or_create_conversation(int(current_user["user_id"]), body.recipient_username)
    recipient = get_user_by_username(body.recipient_username)
    return {
        "conversation_id": conversation["id"],
        "participant": {"username": current_user["username"]},
        "recipient": {"id": recipient["id"], "username": recipient["username"]},
    }


@app.get("/v1/conversations")
def list_conversations(current_user: sqlite3.Row = Depends(get_current_user)) -> list[dict[str, object]]:
    current_user_id = int(current_user["user_id"])
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT c.id, c.created_at,
                   CASE WHEN c.user_a_id = ? THEN u2.username ELSE u1.username END AS other_username
            FROM conversations c
            JOIN users u1 ON u1.id = c.user_a_id
            JOIN users u2 ON u2.id = c.user_b_id
            WHERE c.user_a_id = ? OR c.user_b_id = ?
            ORDER BY c.created_at DESC
            """,
            (current_user_id, current_user_id, current_user_id),
        ).fetchall()
    finally:
        conn.close()
    return [
        {"conversation_id": row["id"], "other_username": row["other_username"], "created_at": row["created_at"]}
        for row in rows
    ]


@app.post("/v1/messages")
def send_message(
    payload: SendMessageRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, object]:
    recipient = get_user_by_username(payload.recipient_username)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")
    conversation = get_or_create_conversation(int(current_user["user_id"]), payload.recipient_username)
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO messages (conversation_id, sender_id, receiver_id, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (conversation["id"], current_user["user_id"], recipient["id"], payload.ciphertext, created_at),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "status": "sent",
        "conversation_id": conversation["id"],
        "recipient_username": recipient["username"],
        "created_at": created_at,
    }


@app.get("/v1/messages")
def get_messages(
    with_user: str = Query(..., alias="with"),
    current_user: sqlite3.Row = Depends(get_current_user),
) -> list[dict[str, object]]:
    recipient = get_user_by_username(with_user)
    if recipient is None:
        raise HTTPException(status_code=404, detail="User was not found.")
    current_user_id = int(current_user["user_id"])
    lower_id, upper_id = sorted((current_user_id, int(recipient["id"])))
    conn = get_db_connection()
    try:
        conversation = conn.execute(
            "SELECT id FROM conversations WHERE user_a_id = ? AND user_b_id = ?",
            (lower_id, upper_id),
        ).fetchone()
        if conversation is None:
            return []
        rows = conn.execute(
            """
            SELECT m.id, m.sender_id, m.receiver_id, m.content, m.created_at,
                   sender.username AS sender_username, receiver.username AS receiver_username
            FROM messages m
            JOIN users sender ON sender.id = m.sender_id
            JOIN users receiver ON receiver.id = m.receiver_id
            WHERE m.conversation_id = ?
            ORDER BY m.id ASC
            """,
            (conversation["id"],),
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row["id"],
            "sender_username": row["sender_username"],
            "receiver_username": row["receiver_username"],
            "ciphertext": row["content"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]
