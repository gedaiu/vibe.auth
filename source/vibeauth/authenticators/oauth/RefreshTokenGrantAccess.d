module vibeauth.authenticators.oauth.RefreshTokenGrantAccess;

import vibeauth.authenticators.oauth.IGrantAccess;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.collections.usercollection;
import vibeauth.data.user;

import std.datetime;
import std.array;
import std.algorithm;

import vibe.data.json;


/// Grant user access based on a refresh token
final class RefreshTokenGrantAccess : IGrantAccess {
  private {
    AuthData data;
    UserCollection collection;
    User user;
  }

  /// setter for the authentication data
  void authData(AuthData authData) {
    this.data = authData;
    cacheData;
  }

  /// setter for the user collection
  void userCollection(UserCollection userCollection) {
    this.collection = userCollection;
    cacheData;
  }

  private void cacheData() {
    if(collection is null || data.refreshToken == "") {
      return;
    }

    user = collection.byToken(data.refreshToken);
    data.scopes = user.getScopes(data.refreshToken).filter!(a => a != "refresh").array;
  }

  /// Validate the refresh token
  bool isValid() {
    if(data.refreshToken == "") {
      return false;
    }

    return user.isValidToken(data.refreshToken, "refresh");
  }

  /// Get the token Json response object
  Json get() {
    auto response = Json.emptyObject;

    if(!isValid) {
      response["error"] = "Invalid `refresh_token`";
      return response;
    }

    auto username = user.email();

    auto accessToken = collection.createToken(username, Clock.currTime + 3601.seconds, data.scopes, "Bearer");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;

    return response;
  }
}