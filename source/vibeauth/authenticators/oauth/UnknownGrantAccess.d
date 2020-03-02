module vibeauth.authenticators.oauth.UnknownGrantAccess;

import vibeauth.authenticators.oauth.IGrantAccess;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.collections.usercollection;

import vibe.data.json;

/// Handle errors during token generation
final class UnknownGrantAccess : IGrantAccess {
  /// Ignores the auth data
  void authData(AuthData) {}

  /// Ignore the user collection
  void userCollection(UserCollection) {}

  /// All the requests are invalid
  bool isValid() {
    return false;
  }

  /// Get an error Json response
  Json get() {
    auto response = Json.emptyObject;
    response["error"] = "Invalid `grant_type` value";

    return response;
  }
}
