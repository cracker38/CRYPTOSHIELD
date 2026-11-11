import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:cryptoshield_ai/api_service.dart';
import 'package:cryptoshield_ai/main.dart';

class FakeCryptoShieldService implements CryptoShieldService {
  String? submittedChallengeToken;
  String? submittedOptionId;
  String? submittedMfaCode;
  final Map<String, List<Map<String, dynamic>>> toolHistory = {};

  @override
  Future<Map<String, dynamic>> adminOverview() async => {
        'counts': {
          'users': 0,
          'active_users': 0,
          'conversations': 0,
          'messages': 0,
        },
        'users': <Map<String, dynamic>>[],
      };

  @override
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  ) async {
    submittedChallengeToken = challengeToken;
    submittedOptionId = optionId;
    return {
      'status': 'mfa_enrollment_required',
      'challenge_token': 'm' * 43,
      'secret': 'JBSWY3DPEHPK3PXP',
      'provisioning_uri':
          'otpauth://totp/CRYPTOSHIELD:candidate%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=CRYPTOSHIELD',
    };
  }

  @override
  Future<Map<String, dynamic>> verifyMfa(
    String challengeToken,
    String code,
  ) async {
    submittedMfaCode = code;
    return {
      'status': 'logged_in',
      'token': 'session-token',
      'user': {
        'id': 'candidate-uid',
        'username': 'candidate@example.com',
        'role': 'user',
      },
      'recovery_codes': ['RECOVERY-ONE', 'RECOVERY-TWO'],
    };
  }

  @override
  Future<void> checkHealth() async {}

  @override
  Future<List<Map<String, dynamic>>> getMessages(String email) async => [];

  @override
  Future<List<Map<String, dynamic>>> getToolHistory(String kind) async =>
      toolHistory[kind] ?? [];

  @override
  Future<Map<String, dynamic>> login(String email, String password) async => {
        'status': 'challenge_required',
        'challenge_token': 'x' * 43,
        'challenge': {
          'question': 'What is the safe response to an unexpected MFA prompt?',
          'options': [
            {'id': 'deny-prompt-001', 'text': 'Deny it and report it.'},
            {'id': 'approve-001', 'text': 'Approve it to stop notifications.'},
          ],
        },
      };

  @override
  Future<void> logout() async {}

  @override
  Future<void> register(String email, String password) async {}

  @override
  Future<Map<String, dynamic>?> restoreUser() async => null;

  @override
  Future<void> reviewUser(String userId, String decision) async {}

  @override
  Future<void> sendMessage(String email, String content) async {}

  @override
  Future<void> saveToolRecord(String kind, String input, String result) async {
    toolHistory.putIfAbsent(kind, () => []).add({
      'input': input,
      'result': result,
      'created_at': 'now',
    });
  }

  @override
  Future<void> setUserActive(String userId, bool isActive) async {}
}

void main() {
  testWidgets('starts with account sign-in and account creation', (
    tester,
  ) async {
    await tester.pumpWidget(
      CryptoShieldApp(service: FakeCryptoShieldService()),
    );
    await tester.pumpAndSettle();

    expect(find.text('Welcome back'), findsOneWidget);
    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text('Demo analyst'), findsNothing);

    await tester.tap(find.text('Request an analyst account'));
    await tester.pumpAndSettle();

    expect(find.text('Create your account'), findsOneWidget);
    expect(find.text('Confirm password'), findsOneWidget);
  });

  testWidgets('registration explains administrator approval without email', (
    tester,
  ) async {
    await tester.pumpWidget(
      CryptoShieldApp(service: FakeCryptoShieldService()),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Request an analyst account'));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byType(TextFormField).at(0),
      'new-user@example.com',
    );
    await tester.enterText(find.byType(TextFormField).at(1), 'StrongPass123!');
    await tester.enterText(find.byType(TextFormField).at(2), 'StrongPass123!');
    await tester.tap(find.text('Request analyst access'));
    await tester.pumpAndSettle();

    expect(
      find.text('Account request submitted for administrator review.'),
      findsOneWidget,
    );
  });

  testWidgets('approved applicant must pass the challenge before sign-in', (
    tester,
  ) async {
    final service = FakeCryptoShieldService();
    Map<String, dynamic>? authenticatedUser;

    await tester.pumpWidget(
      MaterialApp(
        home: AuthPage(
          service: service,
          onAuthenticated: (user) => authenticatedUser = user,
        ),
      ),
    );
    await tester.enterText(
      find.byType(TextFormField).at(0),
      'candidate@example.com',
    );
    await tester.enterText(
        find.byType(TextFormField).at(1), 'StrongPassword123!');
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();

    expect(find.text('Security onboarding'), findsOneWidget);
    expect(authenticatedUser, isNull);
    await tester.tap(find.text('Deny it and report it.'));
    await tester.ensureVisible(find.text('Continue to authenticator setup'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Continue to authenticator setup'));
    await tester.pumpAndSettle();

    expect(find.text('Set up your authenticator'), findsOneWidget);
    await tester.enterText(find.byType(TextField), '123456');
    await tester.tap(find.text('Verify and enable MFA'));
    await tester.pumpAndSettle();

    expect(find.text('Save your recovery codes'), findsOneWidget);
    await tester.tap(find.text('I’ve saved these codes — continue'));
    await tester.pumpAndSettle();

    expect(authenticatedUser?['id'], 'candidate-uid');
    expect(service.submittedChallengeToken, 'x' * 43);
    expect(service.submittedOptionId, 'deny-prompt-001');
    expect(service.submittedMfaCode, '123456');
  });

  testWidgets(
      'analyzer saves submitted input and report before showing success', (
    tester,
  ) async {
    final service = FakeCryptoShieldService();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: AnalyzerPage(service: service)),
      ),
    );
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), '54657374');
    await tester.tap(find.text('Analyze sample'));
    await tester.pumpAndSettle();

    final saved = service.toolHistory['analysis']!.single;
    expect(saved['input'], '54657374');
    expect(saved['result'], contains('Hexadecimal-like: Yes'));
    expect(find.textContaining('PRELIMINARY FORMAT REPORT'), findsOneWidget);
    expect(find.text('Saved analyses'), findsOneWidget);
  });
}
