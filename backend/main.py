from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = str(BASE_DIR / "cryptoshield.db")
SESSION_TTL = timedelta(days=30)

app = FastAPI(
    title="CRYPTOSHIELD AI API",
    version="0.2.0",
    description="SQLite-backed registration, authentication, and encrypted one-to-one messaging APIs.",
)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class UserStatusRequest(BaseModel):
    is_active: bool


class CreateConversationRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=32)


class SendMessageRequest(BaseModel):
    recipient_username: str = Field(min_length=3, max_length=32)
    content: str = Field(min_length=1, max_length=5000)


class MessageQueryRequest(BaseModel):
    with_user: str = Field(alias="with")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
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
                encryption_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
        if "role" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "is_active" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
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
                encryption_key TEXT NOT NULL,
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
        conn.commit()
    finally:
        conn.close()
    bootstrap_admin()


def bootstrap_admin() -> None:
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    if not email and not password:
        return
    if not email or not password:
        raise RuntimeError("Both ADMIN_EMAIL and ADMIN_PASSWORD must be configured together.")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise RuntimeError("ADMIN_EMAIL must be a valid email address.")
    if len(password) < 12:
        raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters.")

    conn = get_db_connection()
    try:
        existing = conn.execute(
            "SELECT id, role FROM users WHERE lower(username) = ?", (email,)
        ).fetchone()
        if existing is None:
            salt, password_hash = hash_password(password)
            conn.execute(
                """
                INSERT INTO users
                    (username, password_hash, password_salt, encryption_key, created_at, role)
                VALUES (?, ?, ?, ?, ?, 'admin')
                """,
                (
                    email,
                    f"{salt}${password_hash}",
                    salt,
                    generate_conversation_key(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        else:
            conn.execute("UPDATE users SET role = 'admin', is_active = 1 WHERE id = ?", (existing["id"],))
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


def get_user_by_username(username: str) -> sqlite3.Row | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE lower(username) = ?", (username.strip().lower(),)
        ).fetchone()
        return row
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return row
    finally:
        conn.close()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = (now + SESSION_TTL).isoformat()
    conn = get_db_connection()
    try:
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?",
            (user_id,),
        )
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

    token = authorization.split(" ", 1)[1].strip()
    conn = get_db_connection()
    try:
        session = conn.execute(
            "SELECT s.*, u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
    finally:
        conn.close()

    if session is None:
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")

    expires_at = datetime.fromisoformat(session["expires_at"])
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session is invalid or expired.")
    if not session["is_active"]:
        raise HTTPException(status_code=403, detail="This account has been disabled.")

    return session


def generate_conversation_key() -> str:
    return Fernet.generate_key().decode("utf-8")


def encrypt_payload(plaintext: str, key: str) -> str:
    return Fernet(key.encode("utf-8")).encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_payload(ciphertext: str, key: str) -> str:
    return Fernet(key.encode("utf-8")).decrypt(ciphertext.encode("utf-8")).decode("utf-8")


def get_or_create_conversation(current_user_id: int, recipient_username: str) -> sqlite3.Row:
    recipient = get_user_by_username(recipient_username)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")

    if recipient["id"] == current_user_id:
        raise HTTPException(status_code=400, detail="A user cannot message themselves.")

    user_a_id, user_b_id = sorted((current_user_id, recipient["id"]))
    conn = get_db_connection()
    try:
        conversation = conn.execute(
            "SELECT * FROM conversations WHERE user_a_id = ? AND user_b_id = ?",
            (user_a_id, user_b_id),
        ).fetchone()

        if conversation is not None:
            return conversation

        encryption_key = generate_conversation_key()
        created_at = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            """
            INSERT INTO conversations (user_a_id, user_b_id, encryption_key, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_a_id, user_b_id, encryption_key, created_at),
        )
        conn.commit()
        return conn.execute(
            "SELECT * FROM conversations WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
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
    username = payload.username.strip().lower()
    password = payload.password

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", username):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")

    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")

    if get_user_by_username(username) is not None:
        raise HTTPException(status_code=409, detail="This username is already registered.")

    salt, password_hash = hash_password(password)
    encryption_key = generate_conversation_key()
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, password_salt, encryption_key, created_at) VALUES (?, ?, ?, ?, ?)",
                (username, f"{salt}${password_hash}", salt, encryption_key, now),
            )
        except sqlite3.IntegrityError as error:
            raise HTTPException(status_code=409, detail="This email is already registered.") from error
        conn.commit()
        user_id = cursor.lastrowid
    finally:
        conn.close()

    return {
        "status": "registered",
        "user": {"id": user_id, "username": username, "role": "user"},
        "message": "Account created. Sign in to continue.",
    }


@app.post("/v1/login")
def login_user(payload: LoginRequest) -> dict[str, object]:
    user = get_user_by_username(payload.username.strip().lower())
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="This account has been disabled.")

    if not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = create_session(int(user["id"]))

    return {
        "status": "logged_in",
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
    }


@app.get("/v1/me")
def get_me(user: sqlite3.Row = Depends(get_current_user)) -> dict[str, object]:
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "created_at": user["created_at"],
    }


@app.post("/v1/logout")
def logout_user(request: Request, user: sqlite3.Row = Depends(get_current_user)) -> dict[str, str]:
    token = request.headers.get("Authorization", "").split(" ", 1)[1].strip()
    conn = get_db_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()
    return {"status": "logged_out"}


def require_admin(user: sqlite3.Row = Depends(get_current_user)) -> sqlite3.Row:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required.")
    return user


@app.get("/v1/admin/overview")
def admin_overview(admin: sqlite3.Row = Depends(require_admin)) -> dict[str, object]:
    conn = get_db_connection()
    try:
        users = conn.execute(
            "SELECT id, username, role, is_active, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
        conversations = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
        messages = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    finally:
        conn.close()
    return {
        "counts": {
            "users": len(users),
            "active_users": sum(bool(user["is_active"]) for user in users),
            "conversations": conversations,
            "messages": messages,
        },
        "users": [
            {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "is_active": bool(user["is_active"]),
                "created_at": user["created_at"],
            }
            for user in users
        ],
    }


@app.patch("/v1/admin/users/{user_id}")
def set_user_status(
    user_id: int,
    payload: UserStatusRequest,
    admin: sqlite3.Row = Depends(require_admin),
) -> dict[str, object]:
    conn = get_db_connection()
    try:
        target = conn.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="User was not found.")
        if target["id"] == admin["id"] and not payload.is_active:
            raise HTTPException(status_code=400, detail="You cannot disable your own account.")
        if target["role"] == "admin" and not payload.is_active:
            active_admins = conn.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise HTTPException(status_code=400, detail="The last active administrator cannot be disabled.")
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (int(payload.is_active), user_id))
        if not payload.is_active:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()
    return {"id": user_id, "username": target["username"], "is_active": payload.is_active}


@app.post("/v1/conversations")
def create_conversation(
    body: CreateConversationRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
) -> dict[str, object]:
    conversation = get_or_create_conversation(int(current_user["id"]), body.recipient_username)
    participant = get_user_by_id(int(current_user["id"]))
    recipient = get_user_by_username(body.recipient_username)
    return {
        "conversation_id": conversation["id"],
        "participant": {"id": participant["id"], "username": participant["username"]},
        "recipient": {"id": recipient["id"], "username": recipient["username"]},
        "encrypted": True,
    }


@app.get("/v1/conversations")
def list_conversations(current_user: sqlite3.Row = Depends(get_current_user)) -> list[dict[str, object]]:
    current_user_id = int(current_user["id"])
    conn = get_db_connection()
    try:
        rows = conn.execute(
            """
            SELECT c.id, c.user_a_id, c.user_b_id, c.created_at,
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
        {
            "conversation_id": row["id"],
            "other_username": row["other_username"],
            "created_at": row["created_at"],
        }
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

    conversation = get_or_create_conversation(int(current_user["id"]), payload.recipient_username)
    ciphertext = encrypt_payload(payload.content.strip(), conversation["encryption_key"])
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO messages (conversation_id, sender_id, receiver_id, content, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (conversation["id"], current_user["id"], recipient["id"], ciphertext, created_at),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "status": "sent",
        "conversation_id": conversation["id"],
        "recipient_username": recipient["username"],
        "content": payload.content.strip(),
        "encrypted": True,
        "created_at": created_at,
    }


@app.get("/v1/messages")
def get_messages(
    with_user: str = Query(..., alias="with"),
    current_user: sqlite3.Row = Depends(get_current_user),
) -> list[dict[str, object]]:
    recipient = get_user_by_username(with_user)
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient user was not found.")

    current_user_id = int(current_user["id"])
    conn = get_db_connection()
    try:
        conversation = conn.execute(
            "SELECT * FROM conversations WHERE (user_a_id = ? AND user_b_id = ?) OR (user_a_id = ? AND user_b_id = ?)",
            (min(current_user_id, recipient["id"]), max(current_user_id, recipient["id"]), min(current_user_id, recipient["id"]), max(current_user_id, recipient["id"])),
        ).fetchone()

        if conversation is None:
            return []

        rows = conn.execute(
            "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
            (conversation["id"],),
        ).fetchall()
    finally:
        conn.close()

    decrypted: list[dict[str, object]] = []
    for row in rows:
        sender = get_user_by_id(int(row["sender_id"]))
        decrypted.append(
            {
                "id": row["id"],
                "conversation_id": row["conversation_id"],
                "sender_username": sender["username"],
                "receiver_username": get_user_by_id(int(row["receiver_id"]))["username"],
                "content": decrypt_payload(row["content"], conversation["encryption_key"]),
                "created_at": row["created_at"],
            }
        )

    return decrypted
