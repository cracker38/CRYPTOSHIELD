import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceIdentity {
  const DeviceIdentity({
    required this.encryptionPrivateKey,
    required this.encryptionPublicKey,
    required this.signingPrivateKey,
    required this.signingPublicKey,
  });

  final String encryptionPrivateKey;
  final String encryptionPublicKey;
  final String signingPrivateKey;
  final String signingPublicKey;

  static Future<DeviceIdentity> generate() async {
    final encryptionPair = await X25519().newKeyPair();
    final signingPair = await Ed25519().newKeyPair();
    return DeviceIdentity(
      encryptionPrivateKey:
          _encode(await encryptionPair.extractPrivateKeyBytes()),
      encryptionPublicKey:
          _encode((await encryptionPair.extractPublicKey()).bytes),
      signingPrivateKey: _encode(await signingPair.extractPrivateKeyBytes()),
      signingPublicKey: _encode((await signingPair.extractPublicKey()).bytes),
    );
  }

  Map<String, String> toJson() => {
        'encryption_private_key': encryptionPrivateKey,
        'encryption_public_key': encryptionPublicKey,
        'signing_private_key': signingPrivateKey,
        'signing_public_key': signingPublicKey,
      };

  factory DeviceIdentity.fromJson(Map<String, dynamic> json) => DeviceIdentity(
        encryptionPrivateKey: json['encryption_private_key'] as String,
        encryptionPublicKey: json['encryption_public_key'] as String,
        signingPrivateKey: json['signing_private_key'] as String,
        signingPublicKey: json['signing_public_key'] as String,
      );

  static String _encode(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}

class IdentityVault {
  IdentityVault([FlutterSecureStorage? storage])
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  String _identityKey(String username) => 'identity:$username';

  Future<void> saveIdentity(String username, DeviceIdentity identity) =>
      _storage.write(
        key: _identityKey(username),
        value: jsonEncode(identity.toJson()),
      );

  Future<void> deleteIdentity(String username) =>
      _storage.delete(key: _identityKey(username));

  Future<DeviceIdentity?> loadIdentity(String username) async {
    final value = await _storage.read(key: _identityKey(username));
    if (value == null) return null;
    return DeviceIdentity.fromJson(jsonDecode(value) as Map<String, dynamic>);
  }

  Future<String?> loadTrustedFingerprint(String username) =>
      _storage.read(key: 'trusted:$username');

  Future<void> trustFingerprint(String username, String fingerprint) =>
      _storage.write(key: 'trusted:$username', value: fingerprint);
}

class EndToEndCrypto {
  static const _version = 1;
  static final _keyAgreement = X25519();
  static final _cipher = AesGcm.with256bits();
  static final _kdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  static final _signer = Ed25519();

  static Future<String> encrypt({
    required String plaintext,
    required String sender,
    required String recipient,
    required String recipientPublicKey,
    required DeviceIdentity identity,
  }) async {
    final context = _context(sender, recipient);
    final payload = <String, Object>{
      'v': _version,
      'sender': sender,
      'recipient': recipient,
      'for_recipient': await _seal(
        plaintext,
        recipientPublicKey,
        context,
      ),
      'for_sender': await _seal(
        plaintext,
        identity.encryptionPublicKey,
        context,
      ),
    };
    final signingPair = await _signer.newKeyPairFromSeed(
      _decode(identity.signingPrivateKey),
    );
    final signature = await _signer.sign(
      utf8.encode(jsonEncode(payload)),
      keyPair: signingPair,
    );
    return jsonEncode({...payload, 'signature': _encode(signature.bytes)});
  }

  static Future<String> decrypt({
    required String envelope,
    required String expectedSender,
    required String recipient,
    required String senderSigningPublicKey,
    required DeviceIdentity identity,
  }) async {
    final decoded = jsonDecode(envelope);
    if (decoded is! Map<String, dynamic> || decoded['v'] != _version) {
      throw const FormatException('Unsupported encrypted message format.');
    }

    final sender = decoded['sender'] as String;
    final target = decoded['recipient'] as String;
    if (sender != expectedSender ||
        (target != recipient && sender != recipient)) {
      throw const FormatException('Encrypted message identity mismatch.');
    }
    final payload = <String, Object>{
      'v': decoded['v'] as int,
      'sender': sender,
      'recipient': target,
      'for_recipient': decoded['for_recipient'] as Map<String, dynamic>,
      'for_sender': decoded['for_sender'] as Map<String, dynamic>,
    };
    final senderKey = SimplePublicKey(
      _decode(senderSigningPublicKey),
      type: KeyPairType.ed25519,
    );
    final signature = Signature(
      _decode(decoded['signature'] as String),
      publicKey: senderKey,
    );
    final signatureValid = await _signer.verify(
      utf8.encode(jsonEncode(payload)),
      signature: signature,
    );
    if (!signatureValid) {
      throw const FormatException('Message signature is invalid.');
    }

    final context = _context(sender, target);
    final boxedMessage = sender == recipient
        ? decoded['for_sender'] as Map<String, dynamic>
        : decoded['for_recipient'] as Map<String, dynamic>;
    final privatePair = await _keyAgreement.newKeyPairFromSeed(
      _decode(identity.encryptionPrivateKey),
    );
    final remoteEphemeralKey = SimplePublicKey(
      _decode(boxedMessage['ephemeral_public_key'] as String),
      type: KeyPairType.x25519,
    );
    final sharedSecret = await _keyAgreement.sharedSecretKey(
      keyPair: privatePair,
      remotePublicKey: remoteEphemeralKey,
    );
    final derivedKey = await _kdf.deriveKey(
      secretKey: sharedSecret,
      nonce: remoteEphemeralKey.bytes,
      info: utf8.encode(context),
    );
    final box = SecretBox(
      _decode(boxedMessage['ciphertext'] as String),
      nonce: _decode(boxedMessage['nonce'] as String),
      mac: Mac(_decode(boxedMessage['mac'] as String)),
    );
    return utf8.decode(
      await _cipher.decrypt(
        box,
        secretKey: derivedKey,
        aad: utf8.encode(context),
      ),
    );
  }

  static Future<String> fingerprint(DeviceIdentity identity) async {
    final hash = await Sha256().hash([
      ..._decode(identity.encryptionPublicKey),
      ..._decode(identity.signingPublicKey),
    ]);
    final hex = hash.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
    return hex.replaceAllMapped(RegExp('.{4}'), (match) => '${match[0]} ');
  }

  static Future<String> fingerprintForPublicKeys({
    required String encryptionPublicKey,
    required String signingPublicKey,
  }) async {
    final hash = await Sha256().hash([
      ..._decode(encryptionPublicKey),
      ..._decode(signingPublicKey),
    ]);
    final hex = hash.bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
    return hex.replaceAllMapped(RegExp('.{4}'), (match) => '${match[0]} ');
  }

  static String _context(String sender, String recipient) =>
      'CRYPTOSHIELD-E2EE-v1|$sender|$recipient';

  static Future<Map<String, String>> _seal(
    String plaintext,
    String publicKey,
    String context,
  ) async {
    final ephemeralPair = await _keyAgreement.newKeyPair();
    final ephemeralPublic = await ephemeralPair.extractPublicKey();
    final sharedSecret = await _keyAgreement.sharedSecretKey(
      keyPair: ephemeralPair,
      remotePublicKey: SimplePublicKey(
        _decode(publicKey),
        type: KeyPairType.x25519,
      ),
    );
    final derivedKey = await _kdf.deriveKey(
      secretKey: sharedSecret,
      nonce: ephemeralPublic.bytes,
      info: utf8.encode(context),
    );
    final box = await _cipher.encrypt(
      utf8.encode(plaintext),
      secretKey: derivedKey,
      aad: utf8.encode(context),
    );
    return {
      'ephemeral_public_key': _encode(ephemeralPublic.bytes),
      'nonce': _encode(box.nonce),
      'ciphertext': _encode(box.cipherText),
      'mac': _encode(box.mac.bytes),
    };
  }

  static String _encode(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  static List<int> _decode(String value) =>
      base64Url.decode(base64Url.normalize(value));
}
