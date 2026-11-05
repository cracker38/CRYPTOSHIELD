import 'dart:convert';

import 'package:http/http.dart' as http;

const apiBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'http://10.0.2.2:8000',
);

class ApiException implements Exception {
  const ApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

class ApiUser {
  const ApiUser({required this.id, required this.username});

  final int id;
  final String username;
}

class AuthSession {
  const AuthSession({required this.token, required this.user});

  final String token;
  final ApiUser user;
}

class PublicIdentity {
  const PublicIdentity({
    required this.username,
    required this.encryptionPublicKey,
    required this.signingPublicKey,
  });

  final String username;
  final String encryptionPublicKey;
  final String signingPublicKey;

  factory PublicIdentity.fromJson(Map<String, dynamic> json) => PublicIdentity(
        username: json['username'] as String,
        encryptionPublicKey: json['encryption_public_key'] as String,
        signingPublicKey: json['signing_public_key'] as String,
      );
}

class ChatMessage {
  const ChatMessage({
    required this.sender,
    required this.recipient,
    required this.ciphertext,
    required this.createdAt,
  });

  final String sender;
  final String recipient;
  final String ciphertext;
  final String createdAt;

  factory ChatMessage.fromJson(Map<String, dynamic> json) => ChatMessage(
        sender: json['sender_username'] as String,
        recipient: json['receiver_username'] as String,
        ciphertext: json['ciphertext'] as String,
        createdAt: json['created_at'] as String,
      );
}

class ConversationSummary {
  const ConversationSummary({
    required this.otherUsername,
    required this.createdAt,
  });

  final String otherUsername;
  final String createdAt;

  factory ConversationSummary.fromJson(Map<String, dynamic> json) =>
      ConversationSummary(
        otherUsername: json['other_username'] as String,
        createdAt: json['created_at'] as String,
      );
}

class CryptoShieldApi {
  CryptoShieldApi({http.Client? client, String? baseUrl})
      : _client = client ?? http.Client(),
        _baseUrl = (baseUrl ?? apiBaseUrl).replaceFirst(RegExp(r'/$'), '');

  final http.Client _client;
  final String _baseUrl;

  Future<AuthSession> register({
    required String username,
    required String password,
    required String encryptionPublicKey,
    required String signingPublicKey,
  }) async {
    await _request(
      'POST',
      '/v1/register',
      body: {
        'username': username,
        'password': password,
        'encryption_public_key': encryptionPublicKey,
        'signing_public_key': signingPublicKey,
      },
    );
    return login(username: username, password: password);
  }

  Future<AuthSession> login({
    required String username,
    required String password,
  }) async {
    final json = await _request(
      'POST',
      '/v1/login',
      body: {'username': username, 'password': password},
    );
    final user = json['user'] as Map<String, dynamic>;
    return AuthSession(
      token: json['token'] as String,
      user:
          ApiUser(id: user['id'] as int, username: user['username'] as String),
    );
  }

  Future<PublicIdentity> getPublicIdentity({
    required String token,
    required String username,
  }) async {
    final json = await _request(
      'GET',
      '/v1/users/${Uri.encodeComponent(username)}/public-key',
      token: token,
    );
    return PublicIdentity.fromJson(json);
  }

  Future<void> createConversation({
    required String token,
    required String username,
  }) async {
    await _request(
      'POST',
      '/v1/conversations',
      token: token,
      body: {'recipient_username': username},
    );
  }

  Future<List<ConversationSummary>> getConversations(String token) async {
    final json = await _request('GET', '/v1/conversations', token: token);
    return (json as List<dynamic>)
        .map((item) =>
            ConversationSummary.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<List<ChatMessage>> getMessages({
    required String token,
    required String withUser,
  }) async {
    final uri = Uri.parse('$_baseUrl/v1/messages').replace(
      queryParameters: {'with': withUser},
    );
    final response = await _client.get(uri, headers: _headers(token));
    final json = _decodeResponse(response);
    return (json as List<dynamic>)
        .map((item) => ChatMessage.fromJson(item as Map<String, dynamic>))
        .toList();
  }

  Future<void> sendMessage({
    required String token,
    required String recipient,
    required String ciphertext,
  }) async {
    await _request(
      'POST',
      '/v1/messages',
      token: token,
      body: {'recipient_username': recipient, 'ciphertext': ciphertext},
    );
  }

  Future<Map<String, dynamic>> getMe(String token) async =>
      await _request('GET', '/v1/me', token: token) as Map<String, dynamic>;

  Future<void> logout(String token) async {
    await _request('POST', '/v1/logout', token: token);
  }

  Map<String, String> _headers(String? token) => {
        'Content-Type': 'application/json',
        if (token != null) 'Authorization': 'Bearer $token',
      };

  Future<dynamic> _request(
    String method,
    String path, {
    String? token,
    Map<String, Object?>? body,
  }) async {
    final uri = Uri.parse('$_baseUrl$path');
    final headers = _headers(token);
    final response = switch (method) {
      'GET' => await _client.get(uri, headers: headers),
      'POST' => await _client.post(
          uri,
          headers: headers,
          body: jsonEncode(body),
        ),
      _ => throw ArgumentError.value(method, 'method'),
    };
    return _decodeResponse(response);
  }

  dynamic _decodeResponse(http.Response response) {
    dynamic json;
    try {
      json = jsonDecode(response.body);
    } on FormatException {
      throw ApiException('The server returned an invalid response.');
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final detail = json is Map<String, dynamic> ? json['detail'] : null;
      throw ApiException(detail is String
          ? detail
          : 'Request failed (${response.statusCode}).');
    }
    return json;
  }

  void close() => _client.close();
}
