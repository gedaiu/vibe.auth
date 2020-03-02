module vibeauth.authenticators.oauth.PasswordGrantAccess;

import vibeauth.authenticators.oauth.IGrantAccess;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.collections.usercollection;

import std.datetime;
import std.array;

import vibe.data.json;

/// Grant user access based on username and password strings
final class PasswordGrantAccess : IGrantAccess {
  private {
    AuthData data;
    UserCollection collection;
  }

  /// setter for the authentication data
  void authData(AuthData authData) {
    this.data = authData;
  }

  /// setter for the user collection
  void userCollection(UserCollection userCollection) {
    this.collection = userCollection;
  }

  /// validate the authentication data
  bool isValid() {
    if(!collection.contains(data.username)) {
      return false;
    }

    if(!collection[data.username].isValidPassword(data.password)) {
      return false;
    }

    return true;
  }

  /// Get the token Json response object
  Json get() {
    auto response = Json.emptyObject;

    if(!isValid) {
      response["error"] = "Invalid password or username";
      return response;
    }

    auto now = Clock.currTime;

    auto user = collection[data.username];
    foreach(token; user.getTokensByType("Bearer").array) {
      if(token.expire < now) {
        user.revoke(token.name);
      }
    }

    foreach(token; user.getTokensByType("Refresh").array) {
      if(token.expire < now) {
        user.revoke(token.name);
      }
    }


    auto accessToken = collection.createToken(data.username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");
    auto refreshToken = collection.createToken(data.username, Clock.currTime + 30.weeks, data.scopes ~ [ "refresh" ], "Refresh");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;
    response["refresh_token"] = refreshToken.name;

    return response;
  }
}