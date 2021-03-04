import 'dart:math';

import 'package:dartz/dartz.dart';
import 'package:fhir_auth/auth/auth_exception.dart';
import 'package:fhir_auth/auth/fhir_client.dart';
import 'package:fhir_auth/storage/oauth_storage.dart';
import 'package:fhir_auth/storage/oauth_token.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:fhir_auth/auth/metadata_discovery_service.dart';

/// the star of our show, who you've all come to see, the Smart object who
/// will provide the client for interacting with the FHIR server
class SmartClient extends FhirClient {
  SmartClient({
    @required this.baseUrl,
    @required String clientId,
    @required String redirectUri,
    @required this.oauthStorage,
    this.launch,
    this.scopes,
    this.additionalParameters,
    this.authUrl,
    this.tokenUrl,
    this.tokenKey,
    String secret,
    @Default(false) this.isLoggedIn,
  }) {
    _redirectUri = redirectUri;
    _clientId = clientId;
    _secret = secret;
  }

  /// used to retrieve the authorization and token endpoints
  MetaDataDiscoveryService metaDataDiscoveryService;

  /// used to store token
  OauthStorage oauthStorage;

  /// token storage  key
  String tokenKey;

  /// specify the baseUrl of the Capability Statement (or conformance
  /// statement for Dstu2). Note this may not be the same as the authentication
  /// server or the FHIR data server
  String baseUrl;

  /// the clientId of your app, must be pre-registered with the authorization
  /// server
  String _clientId;

  /// the redurectUri of your app, must be pre-registered with the authorization
  /// server, need to follow the instructions from flutter_appauth
  /// https://pub.dev/packages/flutter_appauth
  /// about editing files for Android and iOS
  String _redirectUri;

  /// if there are certain launch strings that need to be included
  String launch;

  /// the scopes that will be included with the request
  List<String> scopes;

  /// any additional parameters you'd like to pass as part of this request
  Map<String, String> additionalParameters = <String, String>{};

  /// the authorize Url from the Conformance/Capability Statement
  String authUrl;

  /// the token Url from the Conformance/Capability Statement
  String tokenUrl;

  /// this is for testing, you shouldn't store the secret in the object
  String _secret;

  bool isLoggedIn;

  final FlutterAppAuth appAuth = FlutterAppAuth();

  /// the function when you're ready to request access, be sure to pass in the
  /// the client secret when you make a request if you're creating a confidential
  /// app
  @override
  Future<Unit> login() async {
    if (authUrl == null || tokenUrl == null) {
      try {
        final endpoints =
            await metaDataDiscoveryService.retrieveAuhMetadata(baseUrl);
        authUrl = endpoints.authUrl;
        tokenUrl = endpoints.tokenUrl;
      } catch (e) {
        throw AuthException(e.toString());
      }
    }

    try {
      await _tokens;
    } catch (e) {
      throw AuthException(e.toString());
    }
    isLoggedIn = true;
    return unit;
  }

  @override
  Future<Unit> logout() async {
    await oauthStorage.delete(tokenKey);
    isLoggedIn = false;
    return unit;
  }

  /// attempting to follow convention of other packages, this getter allows one
  /// to call for [authHeaders], it will automatically check if if the
  /// [accessToken] is expired, if so, it will obtain a new one
  @override
  Future<Map<String, String>> get authHeaders async {
    final token = await oauthStorage.read(tokenKey);
    if (token != null) {
      if (DateTime.now().isAfter(token.expiresAt)) {
        await _refresh;
      }
      return {
        'authorization':
            'Bearer ${(await oauthStorage.read(tokenKey)).accessToken}'
      };
    }
    return {};
  }

  /// check if you already logged
  /// the method try to retrieve and validate a token
  @override
  Future<bool> alreadyLoggedIn() async {
    try {
      final token = getToken();
      return token != null;
    } on TokenExpiredException {
      return false;
    }
  }

  /// return auth token for the current authentication
  /// if it's expired, it will automatically request an other token
  Future<OauthToken> getToken() async {
    final token = await oauthStorage.read(tokenKey);
    if (token != null) {
      if (DateTime.now().isAfter(token.expiresAt)) {
        await _refresh;
      }
      return await oauthStorage.read(tokenKey);
    }
    return null;
  }

  Future<Unit> get _tokens async {
    /// this request simply includes all of the parameters we have to this
    /// point. The clientId, the redirect Url, the client secret, the
    /// authorize and token enpoints, a list of scopes, and if there are any
    /// other additional parameters are passed, they are included
    final request = AuthorizationTokenRequest(
      _clientId,
      _redirectUri,
      clientSecret: _secret,
      serviceConfiguration: AuthorizationServiceConfiguration(
        authUrl,
        tokenUrl,
      ),
      scopes: scopes != null ? scopes : null,
    );
    request.additionalParameters = additionalParameters ?? <String, String>{};
    request.additionalParameters['nonce'] = _nonce();
    request.additionalParameters['aud'] = baseUrl;

    final authorization = await appAuth.authorizeAndExchangeCode(request);

    await oauthStorage.save(
        tokenKey,
        OauthToken(
            idToken: authorization.idToken,
            expiresAt: authorization.accessTokenExpirationDateTime,
            accessToken: authorization.accessToken,
            refreshToken: authorization.refreshToken));

    return unit;
  }

  Future<Unit> get _refresh async {
    final refreshToken = (await oauthStorage.read(tokenKey)).refreshToken;
    if (refreshToken == null) {
      throw TokenExpiredException();
    }
    final tokenRequest = TokenRequest(
      _clientId,
      _redirectUri,
      clientSecret: _secret,
      serviceConfiguration: AuthorizationServiceConfiguration(
        authUrl,
        tokenUrl,
      ),
      refreshToken: refreshToken,
      grantType: 'refresh_token',
      scopes: scopes,
      issuer: _clientId,
    );
    tokenRequest.additionalParameters =
        additionalParameters ?? <String, String>{};
    tokenRequest.additionalParameters['nonce'] = _nonce();
    final authorization = await appAuth.token(tokenRequest);
    await oauthStorage.save(
        tokenKey,
        OauthToken(
            idToken: authorization.idToken,
            expiresAt: authorization.accessTokenExpirationDateTime,
            accessToken: authorization.accessToken,
            refreshToken: authorization.refreshToken));
    return unit;
  }

  String _nonce({int length}) {
    const _chars =
        'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    final _rnd = Random();
    return String.fromCharCodes(Iterable.generate(
        length ?? 10, (_) => _chars.codeUnitAt(_rnd.nextInt(_chars.length))));
  }
}
