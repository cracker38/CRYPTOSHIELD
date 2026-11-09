import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/foundation.dart';

class ApiException implements Exception {
  const ApiException(this.message);
  final String message;

  @override
  String toString() => message;
}

abstract interface class CryptoShieldService {
  Future<void> checkHealth();
  Future<void> register(String email, String password);
  Future<Map<String, dynamic>> login(String email, String password);
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  );
  Future<Map<String, dynamic>?> restoreUser();
  Future<void> logout();
  Future<List<Map<String, dynamic>>> getMessages(String email);
  Future<void> sendMessage(String email, String content);
  Future<Map<String, dynamic>> adminOverview();
  Future<void> reviewUser(String userId, String decision);
  Future<void> setUserActive(String userId, bool isActive);
}

class FirebaseService implements CryptoShieldService {
  FirebaseService({
    FirebaseAuth? auth,
    FirebaseFirestore? firestore,
    FirebaseFunctions? functions,
  })  : _auth = auth ?? FirebaseAuth.instance,
        _firestore = firestore ?? FirebaseFirestore.instance,
        _functions =
            functions ?? FirebaseFunctions.instanceFor(region: 'us-central1');

  final FirebaseAuth _auth;
  final FirebaseFirestore _firestore;
  final FirebaseFunctions _functions;

  Future<Map<String, dynamic>> _call(
    String name, [
    Map<String, Object?> data = const {},
  ]) async {
    try {
      final result = await _functions.httpsCallable(name).call<Object?>(data);
      if (result.data is! Map) {
        throw const ApiException('Firebase returned an invalid response.');
      }
      return Map<String, dynamic>.from(result.data! as Map);
    } on FirebaseFunctionsException catch (error) {
      throw ApiException(error.message ?? 'Firebase request failed (${error.code}).');
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firebase request failed (${error.code}).');
    }
  }

  @override
  Future<void> checkHealth() async {
    await _call('healthCheck');
  }

  @override
  Future<void> register(String email, String password) async {
    UserCredential? credential;
    try {
      credential = await _auth.createUserWithEmailAndPassword(
        email: email.trim(),
        password: password,
      );
      final user = credential.user;
      if (user == null) {
        throw const ApiException('Firebase did not create an account.');
      }
      await user.sendEmailVerification();
      await _call('submitRegistration');
      await _auth.signOut();
    } on FirebaseAuthException catch (error) {
      throw ApiException(error.message ?? 'Account registration failed (${error.code}).');
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firebase registration failed (${error.code}).');
    }
  }

  @override
  Future<Map<String, dynamic>> login(String email, String password) async {
    try {
      final credential = await _auth.signInWithEmailAndPassword(
        email: email.trim(),
        password: password,
      );
      var user = credential.user;
      if (user == null) {
        throw const ApiException('Firebase could not load the signed-in account.');
      }
      await user.reload();
      user = _auth.currentUser;
      if (user == null) {
        throw const ApiException('Firebase sign-in expired. Please sign in again.');
      }
      if (!user.emailVerified) {
        await user.sendEmailVerification();
        await _auth.signOut();
        throw const ApiException(
          'Verify your email using the link we sent, then sign in again. A new verification email was sent.',
        );
      }
      await user.getIdToken(true);

      var profile = await _firestore.collection('users').doc(user.uid).get();
      if (!profile.exists) {
        await _call('submitRegistration');
        profile = await _firestore.collection('users').doc(user.uid).get();
      } else {
        await _call('syncEmailVerification');
        profile = await _firestore.collection('users').doc(user.uid).get();
      }
      final accountStatus = profile.data()?['accountStatus'];
      if (accountStatus == 'pending_review') {
        await _auth.signOut();
        throw const ApiException(
          'Your registration is awaiting administrator review.',
        );
      }
      if (accountStatus == 'rejected') {
        await _auth.signOut();
        throw const ApiException('Your registration request was not approved.');
      }
      if (accountStatus == 'disabled') {
        await _auth.signOut();
        throw const ApiException('This account has been disabled.');
      }
      if (accountStatus == 'challenge_required') {
        final result = await _call('beginOnboarding');
        return {
          'status': 'challenge_required',
          'challenge_token': result['challengeToken'],
          'challenge': result['challenge'],
        };
      }
      if (accountStatus != 'active' || profile.data()?['isActive'] != true) {
        await _auth.signOut();
        throw const ApiException('This account is not authorized to sign in.');
      }
      return {
        'status': 'logged_in',
        'user': _userMap(user, profile.data()!),
      };
    } on FirebaseAuthException catch (error) {
      throw ApiException(error.message ?? 'Sign-in failed (${error.code}).');
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firebase sign-in failed (${error.code}).');
    }
  }

  @override
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  ) async {
    final result = await _call('answerOnboarding', {
      'challengeToken': challengeToken,
      'optionId': optionId,
    });
    final user = _auth.currentUser;
    if (user == null) {
      throw const ApiException('Sign in again before completing onboarding.');
    }
    final profile = await _firestore.collection('users').doc(user.uid).get();
    return {
      'status': result['status'],
      'user': _userMap(user, profile.data() ?? const {}),
    };
  }

  @override
  Future<Map<String, dynamic>?> restoreUser() async {
    final user = _auth.currentUser;
    if (user == null) return null;
    try {
      final profile = await _firestore.collection('users').doc(user.uid).get();
      if (!profile.exists ||
          profile.data()?['accountStatus'] != 'active' ||
          profile.data()?['isActive'] != true) {
        await _auth.signOut();
        return null;
      }
      return _userMap(user, profile.data()!);
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firebase profile check failed (${error.code}).');
    }
  }

  Map<String, dynamic> _userMap(User user, Map<String, dynamic> profile) => {
        'id': user.uid,
        'username': profile['email'] ?? user.email,
        'role': profile['role'] ?? 'user',
        'account_status': profile['accountStatus'] ?? 'active',
        'is_active': profile['isActive'] ?? true,
      };

  @override
  Future<void> logout() async {
    try {
      await _auth.signOut();
    } on FirebaseAuthException catch (error) {
      throw ApiException(error.message ?? 'Sign-out failed (${error.code}).');
    }
  }

  Future<String> _conversationId(String email) async {
    final result = await _call('getOrCreateConversation', {'email': email.trim()});
    return result['conversation_id'] as String;
  }

  @override
  Future<List<Map<String, dynamic>>> getMessages(String email) async {
    try {
      final conversationId = await _conversationId(email);
      final messages = await _firestore
          .collection('conversations')
          .doc(conversationId)
          .collection('messages')
          .orderBy('createdAt')
          .get();
      return messages.docs.map((document) {
        final data = document.data();
        final createdAt = data['createdAt'];
        return {
          'id': document.id,
          'sender_username': data['senderEmail'] ?? '',
          'content': data['content'] ?? '',
          'created_at': createdAt is Timestamp
              ? createdAt.toDate().toIso8601String()
              : '',
        };
      }).toList();
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firestore message read failed (${error.code}).');
    }
  }

  @override
  Future<void> sendMessage(String email, String content) async {
    try {
      final user = _auth.currentUser;
      if (user == null) {
        throw const ApiException('Sign in to send messages.');
      }
      final conversationId = await _conversationId(email);
      await _firestore
          .collection('conversations')
          .doc(conversationId)
          .collection('messages')
          .add({
        'senderId': user.uid,
        'senderEmail': user.email,
        'content': content,
        'createdAt': FieldValue.serverTimestamp(),
      });
    } on FirebaseException catch (error) {
      throw ApiException(error.message ?? 'Firestore message write failed (${error.code}).');
    }
  }

  @override
  Future<Map<String, dynamic>> adminOverview() => _call('adminOverview');

  @override
  Future<void> reviewUser(String userId, String decision) async {
    await _call('reviewUser', {'userId': userId, 'decision': decision});
  }

  @override
  Future<void> setUserActive(String userId, bool isActive) async {
    await _call('setUserStatus', {'userId': userId, 'isActive': isActive});
  }
}

class FirebaseStartupException implements Exception {
  const FirebaseStartupException(this.message);
  final String message;
}

Future<void> initializeFirebase() async {
  try {
    await Firebase.initializeApp();
    await FirebaseAppCheck.instance.activate(
      androidProvider:
          kDebugMode ? AndroidProvider.debug : AndroidProvider.playIntegrity,
    );
  } on FirebaseException catch (error) {
    throw FirebaseStartupException(
      error.message ?? 'Firebase initialization failed (${error.code}).',
    );
  }
}
