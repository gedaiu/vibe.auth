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

  /// Login handler for validating the request
  abstract void checkLogin(HTTPServerRequest req, HTTPServerResponse res);
}
