import 'dart:convert';

import 'package:cryptoshield_ai/api_service.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

class MemorySecureStorage extends FlutterSecureStorage {
  MemorySecureStorage(this.values);

  final Map<String, String> values;

  @override
  Future<String?> read({
    required String key,
    IOSOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    MacOsOptions? mOptions,
    WindowsOptions? wOptions,
  }) async =>
      values[key];
}

class CapturingClient extends http.BaseClient {
  final requests = <http.BaseRequest>[];

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    requests.add(request);
    final response = request.url.path.endsWith('/messages') ? '[]' : '{}';
    return http.StreamedResponse(
      Stream.value(utf8.encode(response)),
      200,
      request: request,
    );
  }
}

void main() {
  test('authenticated requests send the stored bearer token', () async {
    final client = CapturingClient();
    final service = ApiCryptoShieldService(
      client: client,
      storage: MemorySecureStorage({
        'cryptoshield_api_session': 'stored-session-token',
      }),
      baseUri: Uri.parse('http://localhost:8000'),
    );

    await service.adminOverview();
    await service.getMessages('user@example.com');

    expect(client.requests, hasLength(2));
    expect(
      client.requests.map((request) => request.headers['Authorization']),
      everyElement('Bearer stored-session-token'),
    );
  });
}
