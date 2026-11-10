# CRYPTOSHIELD Security Control Matrix

## Assessment scope

This matrix describes controls visible in the repository and their current
readiness. It is a source review, not a penetration test, independent security
assessment, or verification of a deployed Firebase project or production
environment. “Implemented” means a control is present in source; it does not
confirm that production is configured or operating correctly.

### Status key

| Status | Meaning |
|---|---|
| Implemented | A corresponding control exists in the application source. |
| Partial | Some protection exists, but important coverage or operational evidence is missing. |
| Gap | No adequate control is established by the reviewed source. |
| Deployment-dependent | Requires configuration or evidence from the live environment. |

### Control matrix

| Domain | Control and current evidence | Status | Priority | Required action / acceptance evidence |
|---|---|---:|---:|---|
| Data access | Firestore rules deny all direct client reads and writes in [`firestore.rules`](./firestore.rules). The API uses the Admin SDK, which bypasses those rules. | Implemented | P1 | Verify the deny-all rules are deployed to the intended project and test denial using an unprivileged client. |
| Identity and passwords | Registration enforces 12–128 characters; passwords are salted and hashed with PBKDF2-HMAC-SHA256 at 310,000 iterations in [`backend/firestore_api.py`](./backend/firestore_api.py). | Implemented | P1 | Keep hash parameters reviewed and versioned; test password and login behavior on each release. |
| Authentication throttling | Onboarding answers are limited to five failed attempts per 15-minute account window. General registration and password-login throttling is not established in the API source. | Partial | P0 | Add shared, distributed throttling for registration and login, with generic failure responses and alerting. Verify limits across multiple API instances. |
| Session lifecycle | Random bearer tokens are stored by SHA-256 digest, expire after 30 days, and are checked on authenticated requests. Admin disable/review flows revoke user sessions. | Partial | P1 | Decide whether 30 days is acceptable; establish session cleanup, rotation/re-authentication policy, and tests for expiry and revocation. |
| Authorization | Authenticated routes resolve the active user from the session; administrator routes require the admin role. Tool history is stored under the authenticated user. | Implemented | P1 | Maintain negative tests for anonymous, non-admin, disabled-user, and cross-account access. |
| Administrator safety | Self-disable and last-active-admin disable are rejected in [`backend/firestore_api.py`](./backend/firestore_api.py). The last-admin check and account update are separate operations. | Partial | P1 | Make administrator status changes transactional and test concurrent disable requests cannot remove the final active administrator. |
| Transport security | The Flutter client blocks non-local HTTP URLs in [`lib/api_service.dart`](./lib/api_service.dart). The API container serves HTTP; the source does not prevent clients from bypassing a reverse proxy and connecting directly. | Partial | P0 | Terminate TLS at the public edge; bind the API to a private interface and block direct public access to port 8000. Configure trusted proxy handling and verify externally that credentials are never accepted over plaintext. |
| Browser origin policy | CORS uses configured origins and allows local development origins in [`backend/firestore_api.py`](./backend/firestore_api.py). CORS is not an authentication control. | Partial | P1 | Set exact production origins, validate the deployed policy, and ensure the production deployment does not rely on development origins. |
| Message confidentiality | Message contents and per-conversation keys are encrypted at rest with Fernet. The server holds the wrapping key and decrypts messages; responses contain plaintext. | Partial | P1 | Do not describe this as end-to-end encryption. For confidential communications, adopt an independently reviewed end-to-end protocol; protect and back up the server key. |
| Input validation | Pydantic request models constrain several input sizes and enumerated values in [`backend/firestore_api.py`](./backend/firestore_api.py). | Partial | P1 | Add boundary and malformed-input tests for every public endpoint; reject blank-after-trimming message content and validate recipient addresses consistently. |
| Auditability | Registration, onboarding, and selected administrator actions write audit events to Firestore. Comprehensive coverage, retention, tamper resistance, and operational alerting are not established. | Partial | P1 | Define required event coverage, retention, access controls, and alert rules; test that security-sensitive actions produce durable records. |
| Infrastructure and operations | The Docker image runs as a non-root user. Firewalling, production TLS, service-account scope, backups, monitoring, patching, and recovery depend on deployment procedures. | Deployment-dependent | P0 | Record and verify a production deployment checklist, least-privilege service identity, tested restore, patch process, and incident-response ownership before public launch. |
| Security verification | Flutter tests and backend tests cover selected client and API behavior. They do not establish penetration-test coverage or production configuration. | Partial | P1 | Run CI analysis and tests on every change; add authorization/throttling regression tests and commission an independent assessment before handling sensitive data. |

## Release gates

Do not treat the application as production-ready for public accounts or
sensitive communications until all P0 actions have an owner and verifiable
evidence. Before each release:

1. Run `flutter analyze`, `flutter test`, and `pytest backend`.
2. Verify production HTTPS, exact CORS origins, deployed Firestore rules, and
   least-privilege server credentials.
3. Confirm authentication throttling, administrator recovery, backup restore,
   and security-event monitoring work in the target environment.
4. Review open P0/P1 actions and record any accepted risk with an owner and
   review date.

The application currently does not provide email ownership verification or
end-to-end message encryption. These are explicit product limitations, not
controls that this matrix considers satisfied.
