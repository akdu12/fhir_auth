import 'dart:convert';

class OauthToken {
  OauthToken(
      {this.accessToken, this.refreshToken, this.expiresAt, this.idToken});

  factory OauthToken.fromJsonAsString(String token) {
    if (token == null) {
      return null;
    }
    final data = jsonDecode(token);
    return OauthToken(
        accessToken: data['access_token'],
        refreshToken: data['refresh_token'],
        idToken: data['id_token'],
        expiresAt:
            DateTime.fromMillisecondsSinceEpoch(data['expires_at'] as int));
  }

  final String accessToken;
  final String refreshToken;
  final DateTime expiresAt;
  final String idToken;

  String toJsonAsString() {
    final token = {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'id_token': idToken,
      'expires_at': expiresAt.millisecondsSinceEpoch
    };
    return jsonEncode(token);
  }

  Map<String, dynamic> parseJwt() {
    final parts = idToken.split('.');
    if (parts.length != 3) {
      throw Exception('invalid token');
    }

    final payload = _decodeBase64(parts[1]);
    final payloadMap = json.decode(payload);
    if (payloadMap is! Map<String, dynamic>) {
      throw Exception('invalid payload');
    }

    return payloadMap;
  }

  String _decodeBase64(String str) {
    String output = str.replaceAll('-', '+').replaceAll('_', '/');

    switch (output.length % 4) {
      case 0:
        break;
      case 2:
        output += '==';
        break;
      case 3:
        output += '=';
        break;
      default:
        throw Exception('Illegal base64url string!"');
    }

    return utf8.decode(base64Url.decode(output));
  }

  @override
  String toString() {
    return toJsonAsString();
  }
}
