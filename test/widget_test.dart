import 'package:flutter_test/flutter_test.dart';

import 'package:cryptoshield_ai/main.dart';

void main() {
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
