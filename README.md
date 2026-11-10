# CRYPTOSHIELD

CRYPTOSHIELD is a Flutter app using Firebase Authentication,
Cloud Firestore, App Check, and trusted Cloud Functions. Account registration,
administrator approval, the onboarding challenge, messaging, and Analyzer/Lab
history use Firebase. The previous FastAPI/SQLite service is no longer used by
the app.

## Firebase project setup

The Android and web clients are configured for the `cryptoshell-a5beb` Firebase
project. Keep `android/app/src/google-services.json` in place locally. It
contains client configuration, not a server credential.

Before deploying, in the Firebase Console:

1. Enable **Authentication → Email/Password**.
   Set the Firebase password policy to require at least 12 characters and
   enable email-enumeration protection.
2. Create the default **Cloud Firestore** database in the region appropriate
   for your team. Database location cannot be changed after creation.
3. Register the Android app (`com.example.cryptoshield_ai`) in **App Check**.
   Configure **Play Integrity** for release builds. Add your release signing
   certificate SHA-256 fingerprint in Firebase/Play Console as required.
   Register the **CryptoShield Web** app with the **Fraud Defense**
   (reCAPTCHA Enterprise) App Check provider. The web client has a public site
   key configured; override it with `FIREBASE_APP_CHECK_RECAPTCHA_SITE_KEY`
   when running or building if needed. Keep any reCAPTCHA secret key private;
   it is not used by the Flutter client.
4. Billing must be enabled for Cloud Functions deployment. App Check debug
   tokens are only for development; run a debug build, copy the generated
   token from the device logs, and register it in **App Check → Manage debug
   tokens**. Never ship a debug token in a release build.
5. Before release, restrict the Android API key to this package/signing
   certificate, review Firebase Auth email templates, and configure monitoring
   and budget alerts.

Install Flutter and the Firebase CLI, sign in, and deploy the rules and
functions from the repository root:

```bash
flutter pub get
npm ci --prefix functions
npm run build --prefix functions
firebase login
firebase deploy --only firestore:rules,firestore:indexes,functions
```

Functions use enforced App Check. Verify the debug App Check token is registered
before testing registration or admin actions; otherwise those callable
operations are intentionally rejected. The web client uses its configured
reCAPTCHA Enterprise site key by default. Override it for another environment
if needed:

```bash
flutter run -d chrome
flutter build web
```

The app checks both App Check and the Firestore-backed `healthCheck` callable
on startup and fails closed with a retryable error if Firebase is unavailable.
Cloud Functions run in `us-central1`.

If startup reports a health-check failure, deploy the functions to the same
Firebase project configured for the app and confirm `healthCheck` appears in
the Firebase Console under **Functions**:

```bash
firebase deploy --project cryptoshell-a5beb --only functions
```

If the function is deployed, inspect its logs and confirm the web App Check
provider/site key is configured for the registered Firebase web app.

## Bootstrap the first administrator

1. Create the administrator account under **Firebase Authentication** using
   Email/Password and verify its email.
2. Use Google Application Default Credentials for a trusted operator account
   with Firebase Authentication and Firestore administration permissions. Do
   not put a service-account key in this repository.
3. Assign the admin custom claim and profile:

```bash
gcloud auth application-default login
npm run set-admin --prefix functions -- admin@example.com
```

Sign out and back in after setting the custom claim. Admin operations require
both the trusted `admin` custom claim and an active admin profile; client
requests cannot grant roles.

## Account and data lifecycle

- New accounts use Firebase Authentication and must verify their email.
- Registration requests are inactive until an administrator approves them.
- An approved user must pass a random, server-verified defensive security
  scenario before Firestore access is enabled. Challenges expire after ten
  minutes, are single-use, and have a five-attempt/15-minute cooldown.
- Admin review, account status changes, and onboarding outcomes are recorded in
  the private `accountAuditLog` collection.
- Analyzer samples/reports and Lab inputs/outputs are stored under the signed-in
  user's `users/{uid}/toolHistory` collection. Each account can read its own
  records; entries are limited to 20,000 characters per input and result, and
  the screens show the 50 most recent entries by tool type.
- Firestore rules deny direct client writes to account profiles, admin records,
  and challenge records. Tool history is limited to its owner and active
  accounts; messaging is limited to active conversation members.
- Firebase App Check is enforced on callable functions. Debug builds use the
  Android debug provider; release builds use Play Integrity.

The challenge is a knowledge check, not identity verification, MFA, or proof
of professional cybersecurity competence. Use a stronger team identity and
access-management process for production.

## Existing SQLite data

The app no longer reads or writes `backend/cryptoshield.db`; that file is left
untouched as a legacy copy. Existing SQLite password hashes cannot be moved
directly into Firebase Authentication. Existing users must create and verify
Firebase accounts, and old messages are not automatically migrated. Export
and migrate old records only with an approved account-mapping and retention
plan; do not copy credentials or service-account keys into the repository.

## Run and validate

Firebase is configured for Android and web, not native Linux desktop. On a
Linux machine, `flutter run` may select Linux automatically and display an
unsupported-platform message. Run in a browser instead:

```bash
flutter run -d web-server
```

Open the local URL printed by Flutter. Alternatively, connect an Android device
or start an Android emulator and run `flutter run -d <device-id>`. Native Linux
Firebase support is not provided by the configured FlutterFire plugins.

```bash
flutter analyze
flutter test
```

Firebase initialization is configured for Android and web. Other platforms
still need their own Firebase app registration and platform-specific setup
before being enabled.

Firestore encrypts stored data at rest, but messages are **not end-to-end
encrypted**: authorized clients can read conversation contents. Do not send
sensitive or confidential material until the system has undergone independent
security review and a suitable end-to-end protocol is implemented.
