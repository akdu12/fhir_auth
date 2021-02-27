class AuthException implements Exception {
  AuthException(this.cause);

  String cause;
}
