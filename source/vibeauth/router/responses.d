module vibeauth.router.responses;

import vibe.http.router;

/// Write the unauthorized message to the server response
void respondUnauthorized(HTTPServerResponse res, string message = "Authorization required", int status = 401) {
  res.statusCode = status;
  res.writeJsonBody([ "error": message ]);
}
