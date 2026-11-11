import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

class ApiException implements Exception {
  const ApiException(this.message, {this.statusCode});

  final String message;
  final int? statusCode;

  @override
  String toString() => message;
}

abstract interface class CryptoShieldService {
  Future<void> checkHealth();
  Future<void> register(String email, String password);
  Future<void> verifyEmail(String token);
  Future<void> resendEmailVerification(String email);
  Future<void> requestPasswordReset(String email);
  Future<void> confirmPasswordReset(String token, String newPassword);
  Future<Map<String, dynamic>> login(String email, String password);
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  );
  Future<Map<String, dynamic>> verifyMfa(String challengeToken, String code);
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

class ApiCryptoShieldService implements CryptoShieldService {
  ApiCryptoShieldService({
    http.Client? client,
    FlutterSecureStorage? storage,
    Uri? baseUri,
  })  : _client = client ?? http.Client(),
        _storage = storage ?? const FlutterSecureStorage(),
        _baseUri = baseUri ?? _defaultBaseUri;

  static const _configuredBaseUrl =
      String.fromEnvironment('CRYPTOSHIELD_API_URL');
  static const _tokenKey = 'cryptoshield_api_session';

  static Uri get _defaultBaseUri {
    if (_configuredBaseUrl.isNotEmpty) {
      return Uri.parse(_configuredBaseUrl);
    }
    if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
      return Uri.parse('http://10.0.2.2:8000');
    }
    return Uri.parse('http://localhost:8000');
  }

  final http.Client _client;
  final FlutterSecureStorage _storage;
  final Uri _baseUri;

  Uri _uri(String path, [Map<String, String>? query]) {
    final normalizedPath =
        '${_baseUri.path.replaceFirst(RegExp(r'/$'), '')}$path';
    return _baseUri.replace(path: normalizedPath, queryParameters: query);
  }

  void _ensureSecureTransport() {
    const localDevelopmentHosts = {'localhost', '127.0.0.1', '::1', '10.0.2.2'};
    final isLocalDevelopmentHttp = _baseUri.scheme == 'http' &&
        localDevelopmentHosts.contains(_baseUri.host.toLowerCase());
    if (_baseUri.scheme != 'https' && !isLocalDevelopmentHttp) {
      throw const ApiException(
        'The CRYPTOSHIELD API must use HTTPS outside local development.',
      );
    }
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, Object?>? body,
    Map<String, String>? query,
    bool authenticated = false,
  }) async {
    _ensureSecureTransport();
    final headers = <String, String>{'Accept': 'application/json'};
    if (body != null) headers['Content-Type'] = 'application/json';
    if (authenticated) {
      final token = await _storage.read(key: _tokenKey);
      if (token == null || token.isEmpty) {
        throw const ApiException('Sign in to continue.');
      }
      headers['Authorization'] = 'Bearer $token';
    }

    final request = http.Request(method, _uri(path, query))
      ..headers.addAll(headers);
    if (body != null) request.body = jsonEncode(body);

    http.Response response;
    try {
      response = await http.Response.fromStream(await _client.send(request));
    } on http.ClientException catch (error) {
      throw ApiException('Could not connect to the CRYPTOSHIELD API: $error');
    } on FormatException catch (error) {
      throw ApiException('The CRYPTOSHIELD API URL is invalid: $error');
    }

    Object? decoded;
    if (response.body.isNotEmpty) {
      try {
        decoded = jsonDecode(response.body);
      } on FormatException {
        throw ApiException(
          'The API returned an invalid response (${response.statusCode}).',
          statusCode: response.statusCode,
        );
      }
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final error = decoded is Map ? decoded['detail'] : null;
      final message = error is String
          ? error
          : error != null
              ? error.toString()
              : 'API request failed (${response.statusCode}).';
      throw ApiException(message, statusCode: response.statusCode);
    }
    if (decoded == null) return <String, dynamic>{};
    if (decoded is Map<String, dynamic>) return decoded;
    throw ApiException(
      'The API returned an unexpected response (${response.statusCode}).',
      statusCode: response.statusCode,
    );
  }

  Future<List<Map<String, dynamic>>> _requestList(
    String path, {
    Map<String, String>? query,
    bool authenticated = false,
  }) async {
    _ensureSecureTransport();
    final headers = <String, String>{'Accept': 'application/json'};
    if (authenticated) {
      final token = await _storage.read(key: _tokenKey);
      if (token == null || token.isEmpty) {
        throw const ApiException('Sign in to continue.');
      }
      headers['Authorization'] = 'Bearer $token';
    }
    http.Response response;
    try {
      response = await _client.get(_uri(path, query), headers: headers);
    } on http.ClientException catch (error) {
      throw ApiException('Could not connect to the CRYPTOSHIELD API: $error');
    }
    Object? decoded;
    try {
      decoded = jsonDecode(response.body);
    } on FormatException {
      throw ApiException(
        'The API returned an invalid response (${response.statusCode}).',
        statusCode: response.statusCode,
      );
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final error = decoded is Map ? decoded['detail'] : null;
      throw ApiException(
        error?.toString() ?? 'API request failed (${response.statusCode}).',
        statusCode: response.statusCode,
      );
    }
    if (decoded is! List) {
      throw const ApiException('The API returned an unexpected list response.');
    }
    return decoded
        .whereType<Map>()
        .map((item) => Map<String, dynamic>.from(item))
        .toList();
  }

  @override
  Future<void> checkHealth() async {
    await _request('GET', '/health');
  }

  @override
  Future<void> register(String email, String password) async {
    await _request(
      'POST',
      '/v1/register',
      body: {'username': email.trim(), 'password': password},
    );
  }

  @override
  Future<void> verifyEmail(String token) async {
    await _request(
      'POST',
      '/v1/email/verify',
      body: {'token': token.trim()},
    );
  }

  @override
  Future<void> resendEmailVerification(String email) async {
    await _request(
      'POST',
      '/v1/email/verification/resend',
      body: {'email': email.trim()},
    );
  }

  @override
  Future<void> requestPasswordReset(String email) async {
    await _request(
      'POST',
      '/v1/password-reset/request',
      body: {'email': email.trim()},
    );
  }

  @override
  Future<void> confirmPasswordReset(String token, String newPassword) async {
    await _request(
      'POST',
      '/v1/password-reset/confirm',
      body: {'token': token.trim(), 'new_password': newPassword},
    );
  }

  @override
  Future<Map<String, dynamic>> login(String email, String password) async {
    final result = await _request(
      'POST',
      '/v1/login',
      body: {'username': email.trim(), 'password': password},
    );
    final token = result['token'];
    if (result['status'] == 'logged_in') {
      if (token is! String || token.isEmpty) {
        throw const ApiException('The API did not return a valid session.');
      }
      await _storage.write(key: _tokenKey, value: token);
    }
    return result;
  }

  @override
  Future<Map<String, dynamic>> answerChallenge(
    String challengeToken,
    String optionId,
  ) async {
    final result = await _request(
      'POST',
      '/v1/onboarding/answer',
      body: {
        'challenge_token': challengeToken,
        'option_id': optionId,
      },
    );
    return result;
  }

  @override
  Future<Map<String, dynamic>> verifyMfa(
    String challengeToken,
    String code,
  ) async {
    final result = await _request(
      'POST',
      '/v1/mfa/verify',
      body: {
        'challenge_token': challengeToken,
        'code': code,
      },
    );
    final token = result['token'];
    if (token is! String || token.isEmpty) {
      throw const ApiException('The API did not return a valid session.');
    }
    await _storage.write(key: _tokenKey, value: token);
    return result;
  }

  @override
  Future<Map<String, dynamic>?> restoreUser() async {
    if (await _storage.read(key: _tokenKey) == null) return null;
    try {
      return await _request('GET', '/v1/me', authenticated: true);
    } on ApiException catch (error) {
      if (error.statusCode == 401 || error.statusCode == 403) {
        await _storage.delete(key: _tokenKey);
        return null;
      }
      rethrow;
    }
  }

  @override
  Future<void> logout() async {
    try {
      await _request('POST', '/v1/logout', authenticated: true);
    } finally {
      await _storage.delete(key: _tokenKey);
    }
  }

  @override
  Future<List<Map<String, dynamic>>> getMessages(String email) =>
      _requestList(
        '/v1/messages',
        query: {'with': email.trim()},
        authenticated: true,
      );

  @override
  Future<void> sendMessage(String email, String content) async {
    await _request(
      'POST',
      '/v1/messages',
      body: {'recipient_username': email.trim(), 'content': content},
      authenticated: true,
    );
  }

  @override
  Future<List<Map<String, dynamic>>> getToolHistory(String kind) {
    if (kind != 'analysis' && kind != 'lab') {
      throw const ApiException('Tool history type is invalid.');
    }
    return _requestList(
      '/v1/tool-history',
      query: {'kind': kind},
      authenticated: true,
    );
  }

  @override
  Future<void> saveToolRecord(String kind, String input, String result) async {
    if ((kind != 'analysis' && kind != 'lab') ||
        input.isEmpty ||
        input.length > 20000 ||
        result.isEmpty ||
        result.length > 20000) {
      throw const ApiException('Tool history entry is invalid or too large.');
    }
    await _request(
      'POST',
      '/v1/tool-history',
      body: {'kind': kind, 'input': input, 'result': result},
      authenticated: true,
    );
  }

  @override
  Future<Map<String, dynamic>> adminOverview() =>
      _request('GET', '/v1/admin/overview', authenticated: true);

  @override
  Future<void> reviewUser(String userId, String decision) async {
    if (decision != 'approve' && decision != 'reject') {
      throw const ApiException('Administrator review decision is invalid.');
    }
    await _request(
      'POST',
      '/v1/admin/users/${Uri.encodeComponent(userId)}/review',
      body: {'decision': decision},
      authenticated: true,
    );
  }

  @override
  Future<void> setUserActive(String userId, bool isActive) async {
    await _request(
      'PATCH',
      '/v1/admin/users/${Uri.encodeComponent(userId)}',
      body: {'is_active': isActive},
      authenticated: true,
    );
  }
}
