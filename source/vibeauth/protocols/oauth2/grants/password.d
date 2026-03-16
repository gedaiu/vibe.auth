module vibeauth.protocols.oauth2.grants.password;

import vibeauth.protocols.oauth2.grants.access;
import vibeauth.protocols.oauth2.authdata;
import vibeauth.identity.usercollection;

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
    auto refreshToken = collection.createToken(data.username, Clock.currTime + 4.weeks, data.scopes ~ [ "refresh" ], "Refresh");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;
    response["refresh_token"] = refreshToken.name;

    return response;
  }
}

version(unittest) {
  import fluent.asserts;
  import vibeauth.identity.usermemory;
  import vibeauth.identity.user;

  private PasswordGrantAccess createPasswordGrant(string username, string password) {
    auto grant = new PasswordGrantAccess();

    auto users = new UserMemoryCollection([]);
    auto user = new User("user@gmail.com", "password123");
    user.username = "testuser";
    user.id = 1;
    users.add(user);

    AuthData data;
    data.username = username;
    data.password = password;

    grant.userCollection = users;
    grant.authData = data;

    return grant;
  }
}

@("isValid returns false when username not in collection")
unittest {
  auto grant = createPasswordGrant("nobody@test.com", "password123");
  grant.isValid.should.equal(false);
}

@("isValid returns false when password is wrong")
unittest {
  auto grant = createPasswordGrant("user@gmail.com", "wrongpassword");
  grant.isValid.should.equal(false);
}

@("isValid returns true with valid email and password")
unittest {
  auto grant = createPasswordGrant("user@gmail.com", "password123");
  grant.isValid.should.equal(true);
}

@("isValid returns true with valid username and password")
unittest {
  auto grant = createPasswordGrant("testuser", "password123");
  grant.isValid.should.equal(true);
}

@("get returns error JSON when credentials invalid")
unittest {
  auto grant = createPasswordGrant("nobody@test.com", "wrong");
  auto response = grant.get;

  response["error"].get!string.should.equal("Invalid password or username");
}

@("get returns access and refresh tokens on valid credentials")
unittest {
  auto grant = createPasswordGrant("user@gmail.com", "password123");
  auto response = grant.get;

  (response["access_token"].type == Json.Type.string).should.equal(true);
  (response["refresh_token"].type == Json.Type.string).should.equal(true);
  response["token_type"].get!string.should.equal("Bearer");
  (response["expires_in"].get!long > 0).should.equal(true);
}

@("get includes requested scopes in tokens")
unittest {
  auto grant = new PasswordGrantAccess();

  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "password123");
  user.id = 1;
  users.add(user);

  AuthData data;
  data.username = "user@gmail.com";
  data.password = "password123";
  data.scopes = ["read", "write"];

  grant.userCollection = users;
  grant.authData = data;

  auto response = grant.get;

  (response["access_token"].type == Json.Type.string).should.equal(true);
  user.isValidToken(response["access_token"].get!string, "read").should.equal(true);
  user.isValidToken(response["access_token"].get!string, "write").should.equal(true);
}