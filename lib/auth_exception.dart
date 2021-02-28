class AuthException implements Exception {
  AuthException(this.cause);

  String cause;

  @override
  String toString() {
    return cause;
  }
}

class TokenExpiredException extends AuthException {
  TokenExpiredException()
      : super('Oauth token has expired and no refresh token was found');
}
