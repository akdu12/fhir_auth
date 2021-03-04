import 'dart:io';

import 'package:dartz/dartz.dart';
import 'package:fhir_auth/auth/fhir_client.dart';
import 'package:flutter/foundation.dart';
import 'package:google_sign_in/google_sign_in.dart';


class GcsClient extends FhirClient {
  GcsClient({@required this.baseUrl, List<String> scopes, String clientId}) {
    googleSignIn = GoogleSignIn(clientId: clientId, scopes: scopes);
  }

  String baseUrl;
  GoogleSignIn googleSignIn;
  bool isLoggedIn = false;

  @override
  Future<Unit> login() async {
    try {
      await googleSignIn.signIn();
    } catch (e) {
      throw HttpException(e);
    }
    isLoggedIn = true;
    return unit;
  }

  @override
  Future<Map<String, String>> get authHeaders async {
    final headers = await googleSignIn.currentUser.authHeaders;
    headers['Content-Type'] = 'application/fhir+json';
    return headers;
  }

  @override
  Future<Unit> logout() async {
    try {
      await googleSignIn.signOut();
    } catch (e) {
      throw HttpException(e);
    }
    isLoggedIn = false;
    return unit;
  }

  /// check if you already logged
  /// the method try to retrieve and validate a token
  @override
  Future<bool> alreadyLoggedIn() async {
    return googleSignIn.isSignedIn();
  }
}
