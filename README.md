# CRYPTOSHIELD

CRYPTOSHIELD is a Flutter client backed by a self-hosted FastAPI service.
Firebase is used only as the persistent Cloud Firestore database: Firebase
Authentication and Cloud Functions are not used by the app. The API handles
accounts, sessions, administrator approval, onboarding, messaging, and tool
history, and accesses Firestore using trusted server credentials.

## Architecture and data migration

- Flutter sends requests only to the FastAPI API. It does not contain Firebase
  client credentials or access Firestore directly.
- The API stores accounts, sessions, onboarding challenges, audit events,
  conversations, messages, and tool history in Firestore.
- Firestore rules deny all direct client reads and writes. The API uses the
  Firebase Admin SDK, which bypasses those rules and must run only on a trusted
  server.
- Existing Firebase Authentication accounts, SQLite accounts, and old
  Firestore records are not automatically migrated. Users must register
  accounts with the API again. Back up existing data before changing rules.
- The API does not send email or verify email ownership. Administrator approval
  remains required before a new account can sign in. Add a verified email
  delivery provider before using the system for public signups.

The Cloud Functions source is no longer part of the Firebase CLI deployment
configuration. Do not deploy it.

## Firebase setup

Use the existing Firebase project `cryptoshell-a5beb` or set
`GOOGLE_CLOUD_PROJECT` to another Firebase project ID. Create its default
Cloud Firestore database. No Firebase Functions API or Firebase Authentication
setup is needed.

The API server needs the Firestore Admin SDK permission on that project:

- On a Google Cloud VM, attach a dedicated service account with the
  `Cloud Datastore User` role and use the VM's Application Default Credentials.
- On another VM, provide Application Default Credentials through the provider's
  identity integration or mount a service-account credential outside the
  repository. Never commit credentials or put them in the Flutter app.

Deploy the deny-all rules from the repository root after backing up any
existing client data:

```bash
firebase deploy --only firestore:rules,firestore:indexes --project cryptoshell-a5beb
```

The rules intentionally prevent direct client access; only the trusted API
server can access Firestore.

## Configure and run the API

Python 3.12 is recommended. Set the project ID, an initial administrator,
allowed web origins, and a persistent message-encryption key. Keep all secrets
outside source control:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
gcloud auth application-default login

export GOOGLE_CLOUD_PROJECT=cryptoshell-a5beb
export ADMIN_EMAIL=admin@example.com
export ADMIN_PASSWORD='use-a-unique-password-of-at-least-12-characters'
export MESSAGE_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export ALLOWED_ORIGINS=http://localhost:5000
uvicorn backend.firestore_api:app --host 0.0.0.0 --port 8000
```

Store `MESSAGE_ENCRYPTION_KEY` persistently and back it up securely. Losing or
rotating it without re-encrypting conversation keys makes saved messages
unreadable. The admin account is created only when the configured email is not
already registered; changing its role requires a separate trusted operator
procedure.

Check `http://localhost:8000/health` before launching the client.

## Run the Flutter app

Fetch the updated packages and start a browser client:

```bash
flutter pub get
flutter run -d web-server --web-port 5000 \
  --dart-define=CRYPTOSHIELD_API_URL=http://localhost:8000
```

For an Android emulator with the API running on the same computer:

```bash
flutter run -d <device-id> \
  --dart-define=CRYPTOSHIELD_API_URL=http://10.0.2.2:8000
```

The client permits plain HTTP only for loopback and the Android emulator's
`10.0.2.2` development address. All other API endpoints must use HTTPS; the
client blocks remote HTTP connections so session tokens are not sent in
plaintext. Set `ALLOWED_ORIGINS` to the exact browser origin(s) serving the app.
Physical phones need a reachable HTTPS API URL; `10.0.2.2` is emulator only.

## Prepare a self-hosted VM deployment

The repo includes `backend/Dockerfile` for building a container. Provisioning
and operating a public VM is outside Firebase and has not been done for you.
Free VM offers can change, may require payment-card verification, and have
resource limits; confirm the provider's terms. Configure a persistent disk,
automatic security updates, firewall rules, HTTPS reverse proxy, backups,
monitoring, and the environment variables above. Give the VM's service identity
only the Firestore permissions it needs. Never expose the API over plain HTTP
on the public internet.

## Development checks

```bash
flutter analyze
flutter test
pip install -r backend/requirements-dev.txt
pytest backend/test_backend.py
```

`backend/main.py` and its SQLite tests are retained as a legacy local backend;
the Flutter app uses `backend/firestore_api.py`.

The message encryption protects stored message contents from casual database
inspection, but the server can decrypt them. It is not end-to-end encryption.
Do not use the app for confidential communications without independent security
review and a suitable end-to-end protocol.

See the [Security Control Matrix](./SECURITY-MATRIX.md) for implemented
protections, readiness gaps, and release gates.
