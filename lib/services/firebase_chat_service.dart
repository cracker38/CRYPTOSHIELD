import 'dart:convert';

import 'package:cloud_firestore/cloud_firestore.dart';

class FirebaseUserProfile {
  const FirebaseUserProfile({
    required this.uid,
    required this.username,
    required this.encryptionPublicKey,
    required this.signingPublicKey,
  });

  final String uid;
  final String username;
  final String encryptionPublicKey;
  final String signingPublicKey;

  factory FirebaseUserProfile.fromJson(
    String uid,
    Map<String, dynamic> json,
  ) =>
      FirebaseUserProfile(
        uid: uid,
        username: json['username'] as String,
        encryptionPublicKey: json['encryptionPublicKey'] as String,
        signingPublicKey: json['signingPublicKey'] as String,
      );
}

class FirebaseConversation {
  const FirebaseConversation({
    required this.id,
    required this.otherUser,
  });

  final String id;
  final FirebaseUserProfile otherUser;
}

class FirebaseChatMessage {
  const FirebaseChatMessage({
    required this.id,
    required this.senderUid,
    required this.sender,
    required this.recipientUid,
    required this.recipient,
    required this.ciphertext,
  });

  final String id;
  final String senderUid;
  final String sender;
  final String recipientUid;
  final String recipient;
  final String ciphertext;

  factory FirebaseChatMessage.fromJson(
    String id,
    Map<String, dynamic> json,
  ) =>
      FirebaseChatMessage(
        id: id,
        senderUid: json['senderUid'] as String,
        sender: json['sender'] as String,
        recipientUid: json['recipientUid'] as String,
        recipient: json['recipient'] as String,
        ciphertext: json['ciphertext'] as String,
      );
}

class UsernameUnavailableException implements Exception {
  const UsernameUnavailableException();

  @override
  String toString() => 'That username is already in use.';
}

class FirebaseChatService {
  FirebaseChatService({FirebaseFirestore? firestore})
      : _firestore = firestore ?? FirebaseFirestore.instance;

  final FirebaseFirestore _firestore;

  Future<FirebaseUserProfile> createProfile({
    required String uid,
    required String username,
    required String encryptionPublicKey,
    required String signingPublicKey,
  }) async {
    final normalizedUsername = username.trim().toLowerCase();
    if (!RegExp(r'^[a-z0-9_]{3,24}$').hasMatch(normalizedUsername)) {
      throw const FormatException(
        'Use 3–24 letters, numbers, or underscores for your username.',
      );
    }

    final usernameRef =
        _firestore.collection('usernames').doc(normalizedUsername);
    final profileRef = _firestore.collection('users').doc(uid);
    await _firestore.runTransaction((transaction) async {
      final usernameSnapshot = await transaction.get(usernameRef);
      final profileSnapshot = await transaction.get(profileRef);
      if (usernameSnapshot.exists || profileSnapshot.exists) {
        throw const UsernameUnavailableException();
      }

      transaction.set(usernameRef, {'uid': uid});
      transaction.set(profileRef, {
        'username': username.trim(),
        'usernameKey': normalizedUsername,
        'encryptionPublicKey': encryptionPublicKey,
        'signingPublicKey': signingPublicKey,
        'createdAt': FieldValue.serverTimestamp(),
      });
    });
    return getProfileByUid(uid);
  }

  Future<FirebaseUserProfile> getProfileByUid(String uid) async {
    final snapshot = await _firestore.collection('users').doc(uid).get();
    final data = snapshot.data();
    if (data == null) {
      throw StateError('This Firebase account has no CRYPTOSHIELD profile.');
    }
    return FirebaseUserProfile.fromJson(uid, data);
  }

  Future<FirebaseUserProfile> getProfileByUsername(String username) async {
    final key = username.trim().toLowerCase();
    final usernameSnapshot =
        await _firestore.collection('usernames').doc(key).get();
    final uid = usernameSnapshot.data()?['uid'];
    if (uid is! String || uid.isEmpty) {
      throw StateError('No account was found for that username.');
    }
    final profile = await getProfileByUid(uid);
    if (profile.username.toLowerCase() != key) {
      throw StateError('The username directory entry is inconsistent.');
    }
    return profile;
  }

  Future<List<FirebaseConversation>> getConversations(String uid) async {
    final snapshots = await _firestore
        .collection('conversations')
        .where('participants', arrayContains: uid)
        .get();
    final conversations =
        await Future.wait(snapshots.docs.map((snapshot) async {
      final participants = List<String>.from(snapshot.data()['participants']);
      final otherUid =
          participants.singleWhere((participant) => participant != uid);
      return FirebaseConversation(
        id: snapshot.id,
        otherUser: await getProfileByUid(otherUid),
      );
    }));
    return conversations;
  }

  Future<String> ensureConversation({
    required String uid,
    required String otherUid,
  }) async {
    final participants = [uid, otherUid]..sort();
    final id = participants
        .map((participant) => base64Url.encode(utf8.encode(participant)))
        .join('.');
    final conversationRef = _firestore.collection('conversations').doc(id);
    await _firestore.runTransaction((transaction) async {
      final snapshot = await transaction.get(conversationRef);
      if (!snapshot.exists) {
        transaction.set(conversationRef, {
          'participants': participants,
          'createdAt': FieldValue.serverTimestamp(),
          'updatedAt': FieldValue.serverTimestamp(),
        });
      }
    });
    return id;
  }

  Future<List<FirebaseChatMessage>> getMessages(String conversationId) async {
    final snapshots = await _firestore
        .collection('conversations')
        .doc(conversationId)
        .collection('messages')
        .orderBy('createdAt')
        .get();
    return snapshots.docs
        .map((snapshot) => FirebaseChatMessage.fromJson(
              snapshot.id,
              snapshot.data(),
            ))
        .toList();
  }

  Future<void> sendMessage({
    required String conversationId,
    required String senderUid,
    required String sender,
    required String recipientUid,
    required String recipient,
    required String ciphertext,
  }) async {
    final conversationRef =
        _firestore.collection('conversations').doc(conversationId);
    final batch = _firestore.batch();
    final messageRef = conversationRef.collection('messages').doc();
    batch.set(messageRef, {
      'senderUid': senderUid,
      'sender': sender,
      'recipientUid': recipientUid,
      'recipient': recipient,
      'ciphertext': ciphertext,
      'createdAt': FieldValue.serverTimestamp(),
    });
    batch.update(conversationRef, {'updatedAt': FieldValue.serverTimestamp()});
    await batch.commit();
  }
}
