module vibeauth.authenticators.BaseAuth;

import vibe.http.router;
import vibe.data.json;
import vibeauth.collections.usercollection;
import vibeauth.router.accesscontrol;

import std.algorithm.searching, std.base64, std.string, std.stdio;

/// The results that that an authenticator can return
enum AuthResult {
  /// The request does not contain valid auth data
  invalidToken,

  /// The request does not contain the required data to perform the request
  unauthorized,

  /// The request can continue because the user has the necessesary rights
  success
}

/// Base class for using authentication with vibe requests
abstract class BaseAuth {

  protected UserCollection collection;

  /// Instantiate the authenticator with an user collection
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
  void permissiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
    setAccessControl(res);

    if(permissiveAuth(req) == AuthResult.unauthorized) {
      respondUnauthorized(res);
    }

    if(permissiveAuth(req) == AuthResult.invalidToken) {
      respondInvalidToken(res);
    }
  }

  abstract {
    /// Auth handler that will fail if a successfull auth was not performed.
    /// This handler is usefull for routes that want to hide information to the
    /// public.
    AuthResult mandatoryAuth(HTTPServerRequest req);

    /// Auth handler that fails only if the auth fields are present and are not valid.
    /// This handler is usefull when a route should return different data when the user is
    /// logged in
    AuthResult permissiveAuth(HTTPServerRequest req);

    /// Set the response code and message to notify the client that it does not have
    /// rights to make the request
    void respondUnauthorized(HTTPServerResponse res);

    /// Set the response code and message to notify the client that
    /// there were a problem with the request
    void respondInvalidToken(HTTPServerResponse res);
  }
}
