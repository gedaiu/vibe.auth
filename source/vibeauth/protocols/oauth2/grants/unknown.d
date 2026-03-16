module vibeauth.protocols.oauth2.grants.unknown;

import vibeauth.protocols.oauth2.grants.access;
import vibeauth.protocols.oauth2.authdata;
import vibeauth.identity.usercollection;

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

version(unittest) {
  import fluent.asserts;
}

@("isValid always returns false")
unittest {
  auto grant = new UnknownGrantAccess();
  grant.isValid.should.equal(false);
}

@("get returns invalid grant_type error")
unittest {
  auto grant = new UnknownGrantAccess();
  auto response = grant.get;

  response["error"].get!string.should.equal("Invalid `grant_type` value");
}
