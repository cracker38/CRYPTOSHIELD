# CRYPTOSHIELD AI — Mobile Starter

A Flutter mobile UI prototype and FastAPI sample-analysis starter for a secure communication and cryptographic intelligence platform.

## Included in this starter

- Flutter navigation shell and dark cybersecurity UI.
- Home/security overview.
- Demo messaging interface (explicitly **not encrypted**).
- Local basic ciphertext-format triage (Base64/hex observations).
- Caesar cipher educational exercise.
- Investigation, profile and security-settings screens.
- FastAPI `/health` and authorized `/v1/analyze` prototype endpoints.

## Important security status

This is a **prototype**, not a production secure messenger. Do not send real secrets or confidential conversations through the demo messaging screen. The UI does not implement end-to-end encryption, account authentication, secure key storage, persistent messaging, file encryption, or production-grade AI.

Before production:
1. Integrate a maintained, independently audited end-to-end encryption protocol/library. Do not invent a protocol.
2. Implement identity verification, prekey lifecycle, forward secrecy, replay protection, device revocation and secure backup.
3. Keep private keys on user devices using platform secure storage; never upload users' private keys to the API.
4. Add authentication, authorization, rate limiting, TLS, secure database access and secret management.
5. Separate production messaging from the opt-in analysis workflow. Never silently expose message plaintext or keys to analysts.
6. Add security review, threat modelling, penetration testing and dependency scanning.

## Run Flutter

Install Flutter and Android Studio, then from this directory:

```bash
flutter pub get
flutter run
```

To build an Android APK:

```bash
flutter build apk --release
```

## Run backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Health check: `http://127.0.0.1:8000/health`

Analyze a sample:

```bash
curl -X POST http://127.0.0.1:8000/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"sample":"U2FsdGVkX1+example","authorization_confirmed":true}'
```

## Suggested production architecture

- Mobile: Flutter
- API: FastAPI
- Database: PostgreSQL
- Realtime delivery: WebSockets
- Queue/cache: Redis
- Attachments: encrypted object storage
- Key management: platform secure storage + managed KMS/HSM for server-owned keys
- Monitoring: OpenTelemetry, Prometheus and Grafana

## Next engineering milestones

1. Real authentication and account/device registration.
2. Audited end-to-end messaging protocol.
3. Persistent conversation and encrypted attachment services.
4. Analysis job persistence, format plugins and explainable findings.
5. Investigation case/evidence workflows with integrity hashes and audit trails.
6. AI classification trained and evaluated on a curated, labelled dataset.
7. Automated tests, threat model and independent security assessment.
