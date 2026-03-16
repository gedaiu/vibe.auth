module vibeauth.authenticators.oauth.AuthorizationCodeGrantAccess;

import vibeauth.authenticators.oauth.IGrantAccess;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.authenticators.oauth.AuthorizationCodeStore;
import vibeauth.authenticators.oauth.pkce;
import vibeauth.collections.usercollection;

import std.datetime;
import std.typecons;

import vibe.data.json;

final class AuthorizationCodeGrantAccess : IGrantAccess {
  private {
    AuthData data;
    UserCollection collection;
    AuthorizationCodeStore codeStore;
    Nullable!AuthorizationCodeData codeData;
  }

  this(AuthorizationCodeStore codeStore) {
    this.codeStore = codeStore;
  }

  void authData(AuthData authData) {
    this.data = authData;
  }

  void userCollection(UserCollection userCollection) {
    this.collection = userCollection;
  }

  bool isValid() {
    if (data.code.length == 0) {
      return false;
    }

    codeData = codeStore.consume(data.code);

    if (codeData.isNull) {
      return false;
    }

    if (data.redirectUri != codeData.get.redirectUri) {
      return false;
    }

    if (!verifyPkce(data.codeVerifier, codeData.get.codeChallenge, codeData.get.codeChallengeMethod)) {
      return false;
    }

    return true;
  }

  Json get() {
    auto response = Json.emptyObject;

    if (!isValid) {
      response["error"] = "Invalid authorization code or PKCE verification failed";
      return response;
    }

    auto userId = codeData.get.userId;
    auto user = collection.byId(userId);
    auto email = user.email;

    auto accessToken = collection.createToken(email, Clock.currTime + 3601.seconds, codeData.get.scopes, "Bearer");
    auto refreshToken = collection.createToken(email, Clock.currTime + 4.weeks, codeData.get.scopes ~ ["refresh"], "Refresh");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;
    response["refresh_token"] = refreshToken.name;

    return response;
  }
}
