import 'gcs_request.dart';
import 'hapi_request.dart';
import 'smart_request.dart';

Future aidbox() async => await smartRequest(
    // add your configs here
//      url: Api.mihinUrl,
//      clientId: Api.mihinClientId,
//      secret: Api.mihinSecret,
//      authUrl: Api.mihinAuthUrl,
//      tokenUrl: Api.mihinTokenUrl,
//      fhirCallback: Api.fhirCallback,
    );

Future azure() async => await smartRequest(
    // add your configs here
    );

Future gcs() async => await gcsRequest(
    // add your configs here
    );

Future hapi() async => await hapiRequest('hapi Url');

Future mihin() async => await smartRequest(
    // add your configs here
    );
