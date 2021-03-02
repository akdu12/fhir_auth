import 'package:fhir_auth/storage/oauth_storage.dart';
import 'package:fhir_auth/storage/oauth_token.dart';

class InMemoryStorage extends OauthStorage {
  final Map<String, OauthToken> _memory = {};

  @override
  Future<void> save(String key, OauthToken token) async {
    _memory[key] = token;
  }

  @override
  Future<OauthToken> read(String key) async {
    return Future.value(_memory[key]);
  }

  @override
  Future<void> delete(String key) async {
    _memory.remove(key);
  }
}
