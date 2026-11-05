# CRYPTOSHIELD AI

Flutter account and one-to-one messaging prototype using Firebase Authentication and Cloud Firestore, with local format triage, a Caesar-cipher exercise, and investigation/profile screens.

## What works

- Email/password account registration, login, and logout through Firebase Authentication.
- Unique usernames and public device keys stored in Cloud Firestore.
- Device-generated X25519 encryption and Ed25519 signing keys. Private keys remain in platform secure storage; only public keys are registered with Firestore.
- Client-side message encryption using ephemeral X25519, HKDF-SHA-256 and AES-256-GCM. Messages are signed with Ed25519 and encrypted separately for the recipient and sender device so both can display the conversation.
- Out-of-band contact fingerprint verification before the app enables sending or reading a conversation.
- Firestore conversation and message storage. Firestore receives ciphertext only; private keys and plaintext stay on the device.
- Restrictive Firestore rules requiring Firebase Authentication and limiting conversation reads/writes to participants.

## Security limitations

This is a functioning **E2EE prototype**, not a production secure messenger. The cryptographic primitives are established, but the message envelope and key lifecycle have not been independently audited. It does **not** implement a Signal-style ratchet or forward secrecy: compromise of a recipient's long-term private key can expose previously recorded messages for that device. Firebase can also deny service, observe account/conversation metadata, or substitute keys if users do not verify fingerprints through a trusted separate channel.

Other limitations include no key recovery, multi-device support, prekey lifecycle, device revocation, message deletion/retention policy, rate limiting, MFA, or production hosting controls. Losing the device's secure-storage keys makes the account's encrypted history unreadable. Use only accounts and data you control; do not send real confidential material until the protocol and deployment receive independent security review.

Before production:
1. Replace or independently review the custom envelope with a maintained, audited E2EE protocol/library that provides a ratchet and forward secrecy. Do not treat primitive selection as protocol validation.
2. Deploy reviewed Firestore rules; configure backups, database permissions, rate limits, monitoring and abuse controls.
3. Design identity/key transparency, multi-device enrollment, recovery and revocation without uploading private keys.
4. Perform threat modelling, dependency review, protocol review and independent penetration testing.

## Firebase setup

The Android Firebase app is configured for package `com.example.cryptoshield_ai` in `android/app/google-services.json`. In the Firebase console:

1. Enable **Email/Password** in Authentication providers.
2. Create/confirm the Cloud Firestore database.
3. Deploy the repository's `firestore.rules` before allowing clients to use the database:

   ```bash
   firebase deploy --only firestore:rules
   ```

Do not replace these rules with public read/write access. The Android app's Firebase API key is a client identifier, not an authorization mechanism; configure API-key restrictions in Google Cloud as appropriate. Firebase configuration for iOS, web, and desktop is not included.

## Run the Flutter app

Install Flutter and Android Studio, then run on Android:

```bash
flutter pub get
flutter run
```

Create a Firebase account with an email, password, and username, then open a conversation by username. Compare the displayed key fingerprint out of band before confirming identity. Existing accounts in the former custom backend are not automatically migrated to Firebase Authentication. This prototype is single-device: account credentials alone cannot restore a lost private key.

## Tests

```bash
flutter test
flutter analyze
```

Flutter tests cover encryption/decryption, signature tampering, and a basic widget smoke check.
