import 'dart:convert';
import 'dart:math';

import 'package:dartz/dartz.dart';
import 'package:fhir/r4.dart';
import 'package:fhir_auth/auth_exception.dart';
import 'package:fhir_auth/storage/oauth_storage.dart';
import 'package:fhir_auth/storage/oauth_token.dart';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:freezed_annotation/freezed_annotation.dart';
import 'package:http/http.dart';

import 'package:fhir_auth/fhir_client.dart';

/// the star of our show, who you've all come to see, the Smart object who
/// will provide the client for interacting with the FHIR server
class SmartClient extends FhirClient {
  SmartClient({
    @required this.baseUrl,
    @required String clientId,
    @required FhirUri redirectUri,
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

  /// used to store token
  OauthStorage oauthStorage;

  /// token storage  key
  String tokenKey;

  /// specify the baseUrl of the Capability Statement (or conformance
  /// statement for Dstu2). Note this may not be the same as the authentication
  /// server or the FHIR data server
  FhirUri baseUrl;

  /// the clientId of your app, must be pre-registered with the authorization
  /// server
  String _clientId;

  /// the redurectUri of your app, must be pre-registered with the authorization
  /// server, need to follow the instructions from flutter_appauth
  /// https://pub.dev/packages/flutter_appauth
  /// about editing files for Android and iOS
  FhirUri _redirectUri;

  /// if there are certain launch strings that need to be included
  String launch;

  /// the scopes that will be included with the request
  List<String> scopes;

  /// any additional parameters you'd like to pass as part of this request
  Map<String, String> additionalParameters = <String, String>{};

  /// the authorize Url from the Conformance/Capability Statement
  FhirUri authUrl;

  /// the token Url from the Conformance/Capability Statement
  FhirUri tokenUrl;

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
        await _getEndpoints;
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
      final token = await getToken();
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
      _redirectUri.toString(),
      clientSecret: _secret,
      serviceConfiguration: AuthorizationServiceConfiguration(
        authUrl.toString(),
        tokenUrl.toString(),
      ),
      scopes: scopes != null ? scopes : null,
    );
    request.additionalParameters = additionalParameters ?? <String, String>{};
    request.additionalParameters['nonce'] = _nonce();
    request.additionalParameters['aud'] = baseUrl.toString();

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
      _redirectUri.toString(),
      clientSecret: _secret,
      serviceConfiguration: AuthorizationServiceConfiguration(
        authUrl.toString(),
        tokenUrl.toString(),
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

  /// Request for the CapabilityStatement (or Conformance) and then identifying
  /// the authUrl endpoint & tokenurl endpoing
  Future<Unit> get _getEndpoints async {
    var thisRequest = '$baseUrl/metadata?mode=full&_format=json';

    var result = await get(Uri.parse(thisRequest));

    if (_errorCodeMap.containsKey(result.statusCode)) {
      if (result.statusCode == 422) {
        thisRequest = thisRequest.replaceFirst(
          '_format=json',
          '_format=application/json',
        );
        result = await get(Uri.parse(thisRequest));
      }
      if (_errorCodeMap.containsKey(result.statusCode)) {
        throw AuthException('StatusCode: ${result.statusCode}\n${result.body}');
      }
    }
    Map<String, dynamic> returnResult;

    /// because I can't figure out why aidbox only has strings not lists for
    /// the referencePolicy field
    if (thisRequest.contains('aidbox')) {
      returnResult = json.decode(result.body.replaceAll(
          '"referencePolicy":"local"', '"referencePolicy":["local"]'));
    } else {
      returnResult = json.decode(result.body);
    }

    final CapabilityStatement capabilityStatement =
        CapabilityStatement.fromJson(returnResult);

    tokenUrl = _getUri(capabilityStatement, 'token');
    authUrl = _getUri(capabilityStatement, 'authorize');

    /// if either authorize or token are still null, we return a failure
    if (authUrl == null) {
      throw AuthException('No Authorize Url in CapabilityStatement');
    }
    if (tokenUrl == null) {
      throw AuthException('No Token Url in CapabilityStatement');
    }
    return unit;
  }

  /// convenience method for finding either the token or authorize endpoint
  FhirUri _getUri(CapabilityStatement capabilityStatement, String type) {
    if (capabilityStatement?.rest == null) {
      return null;
    } else if (capabilityStatement.rest[0]?.security?.extension_ == null) {
      return null;
    } else if (capabilityStatement.rest[0].security.extension_[0]?.extension_ ==
        null) {
      return null;
    } else {
      final statement = capabilityStatement
          .rest[0].security.extension_[0].extension_
          .firstWhere((ext) => ext.url.toString() == type, orElse: () => null);
      if (statement == null) {
        return null;
      } else {
        return statement.valueUri;
      }
    }
  }

  String _nonce({int length}) {
    const _chars =
        'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    final _rnd = Random();
    return String.fromCharCodes(Iterable.generate(
        length ?? 10, (_) => _chars.codeUnitAt(_rnd.nextInt(_chars.length))));
  }

  static const _errorCodeMap = {
    400: 'Bad Request',
    401: 'Not Authorized',
    404: 'Not Found',
    405: 'Method Not Allowed',
    409: 'Version Conflict',
    412: 'Version Conflict',
    422: 'Unprocessable Entity',
  };
}
