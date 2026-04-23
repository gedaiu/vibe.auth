module vibeauth.protocols.oauth2.grants.refresh;

import vibeauth.protocols.oauth2.grants.access;
import vibeauth.protocols.oauth2.authdata;
import vibeauth.identity.usercollection;
import vibeauth.identity.user;

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

version(unittest) {
  import fluent.asserts;
  import vibeauth.identity.usermemory;
  import vibeauth.identity.token;
}

@("isValid returns false when refresh token is empty")
unittest {
  auto grant = new RefreshTokenGrantAccess();

  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "pass");
  user.id = 1;
  users.add(user);

  AuthData data;
  grant.userCollection = users;
  grant.authData = data;

  grant.isValid.should.equal(false);
}

@("isValid returns true with valid refresh token")
unittest {
  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "pass");
  user.id = 1;
  users.add(user);

  auto token = users.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["read", "refresh"], "Refresh");

  auto grant = new RefreshTokenGrantAccess();

  AuthData data;
  data.refreshToken = token.name;

  grant.userCollection = users;
  grant.authData = data;

  grant.isValid.should.equal(true);
}

@("get returns error JSON when refresh token invalid")
unittest {
  auto grant = new RefreshTokenGrantAccess();

  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "pass");
  user.id = 1;
  users.add(user);

  AuthData data;
  grant.userCollection = users;
  grant.authData = data;

  auto response = grant.get;
  response["error"].get!string.should.equal("Invalid `refresh_token`");
}

@("get returns new access token without refresh scope")
unittest {
  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "pass");
  user.id = 1;
  users.add(user);

  auto token = users.createToken("user@gmail.com", Clock.currTime + 3600.seconds, ["read", "write", "refresh"], "Refresh");

  auto grant = new RefreshTokenGrantAccess();

  AuthData data;
  data.refreshToken = token.name;

  grant.userCollection = users;
  grant.authData = data;

  auto response = grant.get;

  (response["access_token"].type == Json.Type.string).should.equal(true);
  response["token_type"].get!string.should.equal("Bearer");
  (response["expires_in"].get!long > 0).should.equal(true);

  auto accessTokenName = response["access_token"].get!string;
  user.isValidToken(accessTokenName, "read").should.equal(true);
  user.isValidToken(accessTokenName, "write").should.equal(true);
  user.isValidToken(accessTokenName, "refresh").should.equal(false);
}

@("refreshed access token keeps the team scope")
unittest {
  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "pass");
  user.id = 1;
  users.add(user);

  auto token = users.createToken("user@gmail.com", Clock.currTime + 3600.seconds,
    ["api", "team:team-42", "refresh"], "Refresh");

  auto grant = new RefreshTokenGrantAccess();

  AuthData data;
  data.refreshToken = token.name;

  grant.userCollection = users;
  grant.authData = data;

  auto response = grant.get;
  auto accessTokenName = response["access_token"].get!string;

  user.isValidToken(accessTokenName, "team:team-42").should.equal(true);
}