module vibeauth.router.baseAuthRouter;

import vibe.http.router;
import vibe.data.json;
import vibeauth.users;
import vibeauth.router.accesscontrol;

import std.algorithm.searching, std.base64, std.string, std.stdio;

enum AuthResult {
  invalidToken,
  unauthorized,
  success
}

/// Base class for using authentication with vibe requests
abstract class BaseAuthRouter {

  protected UserCollection collection;

  ///
  this(UserCollection collection) {
    this.collection = collection;
  }

  /// Auth handler that will fail if a successfull auth was not performed.
  /// This handler is usefull for routes that want to hide information to the
  /// public.
  void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res) {
    setAccessControl(res);

    if(mandatoryAuth(req) == AuthResult.unauthorized) {
      respondUnauthorized(res);
    }

    if(mandatoryAuth(req) == AuthResult.invalidToken) {
      respondInvalidToken(res);
    }
  }

  /// Auth handler that fails only if the auth fields are present and are not valid.
  /// This handler is usefull when a route should return different data when the user is
  /// logged in
  void permisiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
    setAccessControl(res);

    if(permisiveAuth(req) == AuthResult.unauthorized) {
      respondUnauthorized(res);
    }

    if(permisiveAuth(req) == AuthResult.invalidToken) {
      respondInvalidToken(res);
    }
  }

  /// Auth handler that will fail if a successfull auth was not performed.
  /// This handler is usefull for routes that want to hide information to the
  /// public.
  abstract AuthResult mandatoryAuth(HTTPServerRequest req);

  /// Auth handler that fails only if the auth fields are present and are not valid.
  /// This handler is usefull when a route should return different data when the user is
  /// logged in
  abstract AuthResult permisiveAuth(HTTPServerRequest req);

  ///
  void respondUnauthorized(HTTPServerResponse res);

  ///
  void respondInvalidToken(HTTPServerResponse res);
}
