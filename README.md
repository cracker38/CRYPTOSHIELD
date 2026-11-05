# CRYPTOSHIELD AI

Flutter account and one-to-one messaging prototype with a FastAPI ciphertext relay, local format triage, a Caesar-cipher exercise, and investigation/profile screens.

## What works

- Account registration, login, persisted bearer sessions, and logout.
- Device-generated X25519 encryption and Ed25519 signing keys. Private keys remain in platform secure storage; only public keys are registered with the API.
- Client-side message encryption using ephemeral X25519, HKDF-SHA-256 and AES-256-GCM. Messages are signed with Ed25519 and encrypted separately for the recipient and sender device so both can display the conversation.
- Out-of-band contact fingerprint verification before the app enables sending or reading a conversation.
- SQLite-backed account/session/conversation/message APIs. The backend relays and stores ciphertext and does not decrypt messages.

## Security limitations

This is a functioning **E2EE prototype**, not a production secure messenger. The cryptographic primitives are established, but the message envelope and key lifecycle have not been independently audited. It does **not** implement a Signal-style ratchet or forward secrecy: compromise of a recipient's long-term private key can expose previously recorded messages for that device. The backend can also deny service, observe account/conversation metadata, or substitute keys if users do not verify fingerprints through a trusted separate channel.

Other limitations include no key recovery, multi-device support, prekey lifecycle, device revocation, message deletion/retention policy, rate limiting, MFA, or production hosting controls. Losing the device's secure-storage keys makes the account's encrypted history unreadable. Use only accounts and data you control; do not send real confidential material until the protocol and deployment receive independent security review.

Before production:
1. Replace or independently review the custom envelope with a maintained, audited E2EE protocol/library that provides a ratchet and forward secrecy. Do not treat primitive selection as protocol validation.
2. Deploy only behind HTTPS; configure secret management, backups, database permissions, rate limits, monitoring and abuse controls.
3. Design identity/key transparency, multi-device enrollment, recovery and revocation without uploading private keys.
4. Perform threat modelling, dependency review, protocol review and independent penetration testing.

## Run the backend

From the project directory:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Health check: `http://127.0.0.1:8000/health`

The SQLite database defaults to `backend/cryptoshield.db`. Set `CRYPTOSHIELD_DATABASE_PATH` to use another location. The schema migration removes legacy server-decryptable demo conversations and their stored keys; those old messages cannot be preserved as E2EE messages.

## Run the Flutter app

Install Flutter and Android Studio, then:

```bash
flutter pub get
flutter run --dart-define=API_BASE_URL=http://10.0.2.2:8000
```

`10.0.2.2` routes from the Android emulator to the host machine. For a physical device, use a reachable backend address. Android cleartext traffic is enabled for debug builds only; release builds must use HTTPS. Set `API_BASE_URL` to your HTTPS API URL for a real deployment.

Create an account on each device, sign in, open a conversation by username, and compare the displayed key fingerprint out of band before confirming identity. This prototype is single-device: account credentials alone cannot restore a lost private key.

## Tests

```bash
python -m pytest backend/test_backend.py
flutter test
flutter analyze
```

The backend tests verify registration, authentication, public-key distribution, ciphertext-only persistence, conversation access and rejection of unauthenticated requests. Flutter tests cover encryption/decryption, signature tampering, and a basic widget smoke check.
