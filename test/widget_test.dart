import 'package:cryptoshield_ai/main.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('security overview is visible', (tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: HomePage())),
    );

    expect(find.text('Security overview'), findsOneWidget);
    expect(find.text('ACCOUNT CONNECTED'), findsOneWidget);
  });
}
