import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:cloud_functions/cloud_functions.dart';
import 'package:firebase_app_check/firebase_app_check.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'firebase_web_options.dart';

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
  Future<List<Map<String, dynamic>>> getToolHistory(String kind);
  Future<void> saveToolRecord(String kind, String input, String result);
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
      final message =
          error.message ?? 'Firebase request failed (${error.code}).';
      final healthCheckHint = name == 'healthCheck'
          ? '\nConfirm that Cloud Functions are deployed to us-central1. '
              'If healthCheck is deployed, check its Cloud Functions logs '
              'and the web App Check configuration.'
          : '';
      throw ApiException('$message$healthCheckHint');
    } on FirebaseException catch (error) {
      throw ApiException(
          error.message ?? 'Firebase request failed (${error.code}).');
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
    } catch (error) {
      if (credential?.user?.uid == _auth.currentUser?.uid) {
        await _auth.signOut();
      }
      if (error is FirebaseAuthException) {
        throw ApiException(
          error.message ?? 'Account registration failed (${error.code}).',
        );
      }
      if (error is FirebaseException) {
        throw ApiException(
          error.message ?? 'Firebase registration failed (${error.code}).',
        );
      }
      rethrow;
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
        throw const ApiException(
            'Firebase could not load the signed-in account.');
      }
      await user.reload();
      user = _auth.currentUser;
      if (user == null) {
        throw const ApiException(
            'Firebase sign-in expired. Please sign in again.');
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
    } on ApiException {
      await _auth.signOut();
      rethrow;
    } on FirebaseAuthException catch (error) {
      await _auth.signOut();
      throw ApiException(error.message ?? 'Sign-in failed (${error.code}).');
    } on FirebaseException catch (error) {
      await _auth.signOut();
      throw ApiException(
          error.message ?? 'Firebase sign-in failed (${error.code}).');
    }
  }

  @override
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  ) async {
    try {
      return await _call('answerOnboarding', {
        'challengeToken': challengeToken,
        'optionId': optionId,
      });
    } on ApiException {
      await _auth.signOut();
      rethrow;
    }
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
      throw ApiException(
          error.message ?? 'Firebase profile check failed (${error.code}).');
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
    final result =
        await _call('getOrCreateConversation', {'email': email.trim()});
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
      throw ApiException(
          error.message ?? 'Firestore message read failed (${error.code}).');
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
      throw ApiException(
          error.message ?? 'Firestore message write failed (${error.code}).');
    }
  }

  @override
  Future<List<Map<String, dynamic>>> getToolHistory(String kind) async {
    final user = _auth.currentUser;
    if (user == null) {
      throw const ApiException('Sign in to view your saved tool history.');
    }
    if (kind != 'analysis' && kind != 'lab') {
      throw const ApiException('Tool history type is invalid.');
    }
    try {
      final records = await _firestore
          .collection('users')
          .doc(user.uid)
          .collection('toolHistory')
          .where('kind', isEqualTo: kind)
          .orderBy('createdAt', descending: true)
          .limit(50)
          .get();
      return records.docs.map((document) {
        final data = document.data();
        final createdAt = data['createdAt'];
        return {
          'id': document.id,
          'input': data['input'] as String,
          'result': data['result'] as String,
          'created_at': createdAt is Timestamp
              ? createdAt.toDate().toIso8601String()
              : '',
        };
      }).toList();
    } on FirebaseException catch (error) {
      throw ApiException(
          error.message ?? 'Firestore history read failed (${error.code}).');
    }
  }

  @override
  Future<void> saveToolRecord(String kind, String input, String result) async {
    final user = _auth.currentUser;
    if (user == null) {
      throw const ApiException('Sign in to save tool history.');
    }
    if ((kind != 'analysis' && kind != 'lab') ||
        input.isEmpty ||
        input.length > 20000 ||
        result.isEmpty ||
        result.length > 20000) {
      throw const ApiException('Tool history entry is invalid or too large.');
    }
    try {
      await _firestore
          .collection('users')
          .doc(user.uid)
          .collection('toolHistory')
          .add({
        'kind': kind,
        'input': input,
        'result': result,
        'createdAt': FieldValue.serverTimestamp(),
      });
    } on FirebaseException catch (error) {
      throw ApiException(
          error.message ?? 'Firestore history write failed (${error.code}).');
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
  if (!kIsWeb && defaultTargetPlatform != TargetPlatform.android) {
    throw FirebaseStartupException(
      'Firebase is not configured for ${defaultTargetPlatform.name} desktop. '
      'This app supports Android and web. Run `flutter run -d web-server` '
      'and open the local URL in a browser, or connect an Android device. '
      'Native Linux Firebase support is not available in the configured plugins.',
    );
  }

  const appCheckSiteKey = String.fromEnvironment(
    'FIREBASE_APP_CHECK_RECAPTCHA_SITE_KEY',
    defaultValue: '6LcppBguAAAAAAqvD2LjpSBXVzM9lJeNJ34Hc0bu',
  );

  try {
    if (kIsWeb) {
      await Firebase.initializeApp(options: firebaseWebOptions);
      await FirebaseAppCheck.instance.activate(
        providerWeb: ReCaptchaEnterpriseProvider(appCheckSiteKey),
      );
    } else {
      await Firebase.initializeApp();
      await FirebaseAppCheck.instance.activate(
        providerAndroid: kDebugMode
            ? const AndroidDebugProvider()
            : const AndroidPlayIntegrityProvider(),
      );
    }
  } on FirebaseException catch (error) {
    throw FirebaseStartupException(
      error.message ?? 'Firebase initialization failed (${error.code}).',
    );
  } on PlatformException catch (error) {
    throw FirebaseStartupException(
      error.message ?? 'Firebase platform setup failed (${error.code}).',
    );
  } on MissingPluginException {
    throw const FirebaseStartupException(
      'Firebase plugins are missing. Rebuild the app after fetching packages.',
    );
  }
}
