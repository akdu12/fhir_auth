import 'package:fhir_auth/storage/oauth_token.dart';

abstract class OauthStorage {
  Future<void> save(String key, OauthToken token);

  Future<OauthToken> read(String key);

  Future<void> delete(String key);
}
