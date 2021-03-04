import 'dart:convert';

import 'package:fhir/dstu2.dart' as dstu2;
import 'package:fhir/r4.dart' as r4;
import 'package:fhir/r5.dart' as r5;
import 'package:fhir/stu3.dart' as stu3;
import 'package:fhir_auth/auth/auth_exception.dart';
import 'package:http/http.dart';

/// this class helps find the authorization and token url using the [/metadata]
/// endpoint.the service support the fhir server version including latest one r5

class MetaDataDiscoveryService {
  MetaDataDiscoveryService._(this._version);

  factory MetaDataDiscoveryService.r4() {
    return MetaDataDiscoveryService._(FhirServerVersion.r4);
  }

  factory MetaDataDiscoveryService.r5() {
    return MetaDataDiscoveryService._(FhirServerVersion.r5);
  }

  factory MetaDataDiscoveryService.dstu2() {
    return MetaDataDiscoveryService._(FhirServerVersion.dstu2);
  }

  factory MetaDataDiscoveryService.stu3() {
    return MetaDataDiscoveryService._(FhirServerVersion.stu3);
  }

  FhirServerVersion _version;

  /// Request for the CapabilityStatement (or Conformance) and then identifying
  /// the authUrl endpoint & tokenUrl endpoint.
  /// throw a AuthException exception when no metadata was found
  Future<AuthMetaData> retrieveAuhMetadata(String issuer) async {
    var thisRequest = '$issuer/metadata?mode=full&_format=json';

    var result = await get(thisRequest);

    if (_errorCodeMap.containsKey(result.statusCode)) {
      if (result.statusCode == 422) {
        thisRequest = thisRequest.replaceFirst(
          '_format=json',
          '_format=application/json',
        );
        result = await get(thisRequest,
            headers: {'Accept': 'application/fhir+json'});
      }
      if (_errorCodeMap.containsKey(result.statusCode)) {
        throw AuthException('StatusCode: ${result.statusCode}\n${result.body}');
      }
    }
    Map<String, dynamic> json = {};

    /// because I can't figure out why aidbox only has strings not lists for
    /// the referencePolicy field
    if (thisRequest.contains('aidbox')) {
      json = jsonDecode(result.body.replaceAll(
          '"referencePolicy":"local"', '"referencePolicy":["local"]'));
    } else {
      json = jsonDecode(result.body);
    }

    final tokenUrl = parseJson(json, 'token');
    final authUrl = parseJson(json, 'authorize');
    if (tokenUrl == null || authUrl == null) {
      throw AuthException('Enable to find Authorization and Token Url');
    }

    return AuthMetaData(authUrl: authUrl, tokenUrl: tokenUrl);
  }

  String parseJson(Map<String, dynamic> json, String type) {
    switch (_version) {
      case FhirServerVersion.r5:
        return _r5Parser(json, type);
      case FhirServerVersion.r4:
        return _r4Parser(json, type);
      case FhirServerVersion.stu3:
        return _stu3Parser(json, type);
      case FhirServerVersion.dstu2:
        return _dstu2Parser(json, type);
      default:
        return null;
    }
  }

  String _stu3Parser(Map<String, dynamic> json, String type) {
    final stu3.CapabilityStatement capabilityStatement =
        stu3.CapabilityStatement.fromJson(json);

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
        return statement.valueUri.toString();
      }
    }
  }

  String _r4Parser(Map<String, dynamic> json, String type) {
    final r4.CapabilityStatement capabilityStatement =
        r4.CapabilityStatement.fromJson(json);

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
        return statement.valueUri.toString();
      }
    }
  }

  /// convenience method for finding either the token or authorize endpoint
  String _r5Parser(Map<String, dynamic> json, String type) {
    final r5.CapabilityStatement capabilityStatement =
        r5.CapabilityStatement.fromJson(json);

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
        return statement.valueUri.toString();
      }
    }
  }

  String _dstu2Parser(Map<String, dynamic> json, String type) {
    final dstu2.CapabilityStatement capabilityStatement =
        dstu2.CapabilityStatement.fromJson(json);
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
        return statement.valueUri.toString();
      }
    }
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

enum FhirServerVersion { r5, r4, stu3, dstu2 }

class AuthMetaData {
  AuthMetaData({this.tokenUrl, this.authUrl});

  final String authUrl;
  final String tokenUrl;
}
