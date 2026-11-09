# CRYPTOSHIELD

CRYPTOSHIELD is a Flutter security workspace backed by a FastAPI service. It
provides account registration and sign-in, role-protected account
administration, server-persisted messaging, local sample triage and a local
classical-cipher training exercise.

## Run the backend

Use Python 3.10+ and install the dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Configure the initial administrator through your shell or a secrets manager.
The account is created the first time the backend starts with these values;
the password is hashed and is not written to source code:

```bash
export ADMIN_EMAIL='it.elias38@gmail.com'
export ADMIN_PASSWORD='choose-a-unique-password-of-at-least-12-characters'
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Set both variables together. On startup, an account matching `ADMIN_EMAIL` is
granted the administrator role; if the account does not exist, it is created
with `ADMIN_PASSWORD`. Keep the password in a secret manager and do not commit
it to the repository. New accounts can be created from the app and require an
email address and a password of at least 12 characters.

Health check: `http://127.0.0.1:8000/health`

## Run the Flutter app

Install Flutter, fetch the packages and launch:

```bash
flutter pub get
flutter run
```

The default API address is `http://127.0.0.1:8000` (desktop/local). For an
Android emulator, use the host machine's emulator bridge:

```bash
flutter run --dart-define=API_BASE_URL=http://10.0.2.2:8000
```

For a physical device, set `API_BASE_URL` to the backend host reachable over
your network. Use HTTPS for any non-local deployment.

## API capabilities

- `POST /v1/register`, `POST /v1/login`, `GET /v1/me`, `POST /v1/logout`
- `GET /v1/conversations`, `POST /v1/conversations`
- `GET /v1/messages`, `POST /v1/messages`
- Administrator-only `GET /v1/admin/overview`
- Administrator-only `PATCH /v1/admin/users/{id}` to disable or re-enable an account

Run backend tests from the repository root with `python -m pytest`.

## Security boundaries

This is an operational starter, not a production-ready secure messenger.
Message bodies are encrypted in the SQLite database using a server-managed
key, but this is **not end-to-end encryption**: the server can decrypt
messages. Do not send sensitive or confidential content. The login token is
held in memory by the app and is cleared on sign-out.

Before handling real secrets or deploying publicly:

1. Use TLS, production-grade secret management, backups, monitoring and
   database access controls.
2. Move from SQLite to a managed database and add rate limiting, account
   recovery, email verification, audit events and stronger session lifecycle
   controls.
3. Use a maintained, independently audited end-to-end encryption protocol.
   Do not invent a protocol or upload private keys.
4. Add secure device storage, identity verification, forward secrecy,
   attachment encryption, replay protection, threat modelling and independent
   security testing.
5. Keep analysis opt-in, authorized and separate from messaging.
