import 'package:flutter_test/flutter_test.dart';

import 'package:cryptoshield_ai/firebase_service.dart';
import 'package:cryptoshield_ai/main.dart';

class FakeCryptoShieldService implements CryptoShieldService {
  String? submittedChallengeToken;
  String? submittedOptionId;

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
      'status': 'logged_in',
      'user': {
        'id': 'candidate-uid',
        'username': 'candidate@example.com',
        'role': 'user',
      },
    };
  }

  @override
  Future<void> checkHealth() async {}

  @override
  Future<List<Map<String, dynamic>>> getMessages(String email) async => [];

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

    await tester.tap(find.text('New here? Create an account'));
    await tester.pumpAndSettle();

    expect(find.text('Create your account'), findsOneWidget);
    expect(find.text('Confirm password'), findsOneWidget);
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
    await tester.enterText(find.byType(TextFormField).at(1), 'StrongPassword123!');
    await tester.tap(find.text('Sign in'));
    await tester.pumpAndSettle();

    expect(find.text('Security onboarding'), findsOneWidget);
    expect(authenticatedUser, isNull);
    await tester.tap(find.text('Deny it and report it.'));
    await tester.ensureVisible(find.text('Submit answer'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Submit answer'));
    await tester.pumpAndSettle();

    expect(authenticatedUser?['id'], 'candidate-uid');
    expect(service.submittedChallengeToken, 'x' * 43);
    expect(service.submittedOptionId, 'deny-prompt-001');
  });
}
