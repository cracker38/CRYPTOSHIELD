import 'dart:convert';

import 'package:cryptoshield_ai/security/identity_vault.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('recipient and sender can decrypt; tampering is rejected', () async {
    final alice = await DeviceIdentity.generate();
    final bob = await DeviceIdentity.generate();
    const plaintext = 'Defensive test message 🔐';
    final ciphertext = await EndToEndCrypto.encrypt(
      plaintext: plaintext,
      sender: 'alice',
      recipient: 'bob',
      recipientPublicKey: bob.encryptionPublicKey,
      identity: alice,
    );

    final received = await EndToEndCrypto.decrypt(
      envelope: ciphertext,
      expectedSender: 'alice',
      recipient: 'bob',
      senderSigningPublicKey: alice.signingPublicKey,
      identity: bob,
    );
    final senderCopy = await EndToEndCrypto.decrypt(
      envelope: ciphertext,
      expectedSender: 'alice',
      recipient: 'alice',
      senderSigningPublicKey: alice.signingPublicKey,
      identity: alice,
    );
    expect(received, plaintext);
    expect(senderCopy, plaintext);
    expect(ciphertext, isNot(contains(plaintext)));

    final tampered = jsonDecode(ciphertext) as Map<String, dynamic>;
    tampered['recipient'] = 'mallory';
    await expectLater(
      EndToEndCrypto.decrypt(
        envelope: jsonEncode(tampered),
        expectedSender: 'alice',
        recipient: 'bob',
        senderSigningPublicKey: alice.signingPublicKey,
        identity: bob,
      ),
      throwsA(isA<FormatException>()),
    );
  });
}
