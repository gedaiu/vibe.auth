module vibeauth.router.baseAuthRouter;

import vibe.http.router;
import vibe.data.json;
import vibeauth.users;

import std.algorithm.searching, std.base64, std.string, std.stdio;

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
  abstract void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res);

  /// Auth handler that fails only if the auth fields are present and are not valid.
  /// This handler is usefull when a route should return different data when the user is 
  /// logged in
  abstract void permisiveAuth(HTTPServerRequest req, HTTPServerResponse res);
}
