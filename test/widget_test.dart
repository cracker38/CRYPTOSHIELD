import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:cryptoshield_ai/main.dart';

void main() {
  test('reports the configured API URL when the server is unreachable', () {
    final api = ApiClient(
      client: MockClient((_) => throw const SocketException('connection refused')),
    );

    expect(
      api.request('GET', '/health'),
      throwsA(
        isA<ApiException>().having(
          (error) => error.message,
          'message',
          allOf(contains(apiBaseUrl), contains('Start the API')),
        ),
      ),
    );
  });

  testWidgets('starts with account sign-in and account creation', (
    tester,
  ) async {
    await tester.pumpWidget(const CryptoShieldApp());

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
    final api = ApiClient(
      client: MockClient((request) async {
        if (request.url.path == '/v1/login') {
          return httpResponse({
            'status': 'challenge_required',
            'challenge_token': 'x' * 43,
            'challenge': {
              'question': 'What is the safe response to an unexpected MFA prompt?',
              'options': [
                {'id': 'deny-prompt-001', 'text': 'Deny it and report it.'},
                {'id': 'approve-001', 'text': 'Approve it to stop notifications.'},
              ],
            },
          });
        }
        if (request.url.path == '/v1/onboarding/answer') {
          final body = jsonDecode(request.body) as Map<String, dynamic>;
          expect(body['challenge_token'], 'x' * 43);
          expect(body['option_id'], 'deny-prompt-001');
          return httpResponse({
            'status': 'logged_in',
            'token': 'session-token',
            'user': {'id': 42, 'username': 'candidate@example.com', 'role': 'user'},
          });
        }
        throw StateError('Unexpected API endpoint: ${request.url.path}');
      }),
    );
    Map<String, dynamic>? authenticatedUser;

    await tester.pumpWidget(
      MaterialApp(
        home: AuthPage(
          api: api,
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

    expect(authenticatedUser?['id'], 42);
    expect(api.token, 'session-token');
  });
}

http.Response httpResponse(Map<String, dynamic> body) => http.Response(
      jsonEncode(body),
      200,
      headers: {'content-type': 'application/json'},
    );
