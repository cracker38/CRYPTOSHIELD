import 'dart:io';

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
}
