module vibeauth.router.responses;

import vibe.http.router;

/// Write the unauthorized message to the server response
void respondUnauthorized(HTTPServerResponse res, string message = "Authorization required") {
  res.statusCode = HTTPStatus.unauthorized;
  res.writeJsonBody([ "error": message ]);
}
