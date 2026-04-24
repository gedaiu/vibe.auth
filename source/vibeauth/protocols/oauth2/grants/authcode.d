module vibeauth.protocols.oauth2.grants.authcode;

import vibeauth.protocols.oauth2.grants.access;
import vibeauth.protocols.oauth2.authdata;
import vibeauth.protocols.oauth2.codestore;
import vibeauth.protocols.oauth2.pkce;
import vibeauth.identity.usercollection;

import std.datetime;
import std.typecons;

import vibe.data.json;

version(unittest) {
  import fluent.asserts;
  import vibeauth.identity.usermemory;
  import vibeauth.identity.user;
  import std.digest.sha;
  import std.base64;
}

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

    auto accessLifetime = codeData.get.expiresIn > 0
      ? codeData.get.expiresIn.seconds
      : defaultAccessTokenLifetime.seconds;
    auto refreshLifetime = accessLifetime + 4.weeks;

    auto accessToken = collection.createToken(email, Clock.currTime + accessLifetime, codeData.get.scopes, "Bearer");
    auto refreshToken = collection.createToken(email, Clock.currTime + refreshLifetime, codeData.get.scopes ~ ["refresh"], "Refresh");

    response["access_token"] = accessToken.name;
    response["expires_in"] = (accessToken.expire - Clock.currTime).total!"seconds";
    response["token_type"] = accessToken.type;
    response["refresh_token"] = refreshToken.name;

    return response;
  }
}

version(unittest) {

private AuthorizationCodeGrantAccess createTestGrant(AuthorizationCodeStore store) {
  auto grant = new AuthorizationCodeGrantAccess(store);

  auto users = new UserMemoryCollection([]);
  auto user = new User("user@gmail.com", "password");
  user.id = 1;
  users.add(user);

  grant.userCollection = users;
  return grant;
}

private string makeChallenge(string verifier) {
  auto hash = sha256Of(cast(const(ubyte)[]) verifier);
  string encoded = Base64URL.encode(hash[]).idup;

  while (encoded.length > 0 && encoded[$ - 1] == '=') {
    encoded = encoded[0 .. $ - 1];
  }

  return encoded;
}

@("isValid returns false when code is empty")
unittest {
  auto store = new AuthorizationCodeStore();
  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "";
  grant.authData = data;

  grant.isValid.should.equal(false);
}

@("isValid returns false when code does not exist in store")
unittest {
  auto store = new AuthorizationCodeStore();
  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "nonexistent-code";
  grant.authData = data;

  grant.isValid.should.equal(false);
}

@("isValid returns false when redirect_uri does not match")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://evil.example.com/callback";
  data.codeVerifier = verifier;
  grant.authData = data;

  grant.isValid.should.equal(false);
}

@("isValid returns false when PKCE verifier does not match challenge")
unittest {
  auto store = new AuthorizationCodeStore();

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge("correct-verifier");
  codeData.codeChallengeMethod = "S256";
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = "wrong-verifier";
  grant.authData = data;

  grant.isValid.should.equal(false);
}

@("isValid returns true with valid code, redirect_uri, and PKCE verifier")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = verifier;
  grant.authData = data;

  grant.isValid.should.equal(true);
}

@("get returns error JSON when validation fails")
unittest {
  auto store = new AuthorizationCodeStore();
  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "";
  grant.authData = data;

  auto response = grant.get;
  response["error"].get!string.should.equal("Invalid authorization code or PKCE verification failed");
}

@("get returns access and refresh tokens on valid authorization code")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  codeData.scopes = ["read", "write"];
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = verifier;
  grant.authData = data;

  auto response = grant.get;

  (response["access_token"].type == Json.Type.string).should.equal(true);
  (response["refresh_token"].type == Json.Type.string).should.equal(true);
  response["token_type"].get!string.should.equal("Bearer");
  (response["expires_in"].get!long > 0).should.equal(true);
}

@("get honors stored expiresIn for the access token")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  codeData.expiresIn = 2592000;
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = verifier;
  grant.authData = data;

  auto response = grant.get;
  auto expiresIn = response["expires_in"].get!long;

  (expiresIn > 2592000 - 5 && expiresIn <= 2592000).should.equal(true);
}

@("get falls back to default lifetime when stored expiresIn is zero")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "test-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  store.store(codeData);

  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "test-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = verifier;
  grant.authData = data;

  auto response = grant.get;
  auto expiresIn = response["expires_in"].get!long;

  (expiresIn > defaultAccessTokenLifetime - 5 && expiresIn <= defaultAccessTokenLifetime).should.equal(true);
}

@("isValid consumes code so it cannot be reused")
unittest {
  auto store = new AuthorizationCodeStore();
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

  AuthorizationCodeData codeData;
  codeData.code = "one-time-code";
  codeData.userId = "1";
  codeData.redirectUri = "https://app.example.com/callback";
  codeData.codeChallenge = makeChallenge(verifier);
  codeData.codeChallengeMethod = "S256";
  store.store(codeData);

  auto grant1 = createTestGrant(store);
  AuthData data;
  data.code = "one-time-code";
  data.redirectUri = "https://app.example.com/callback";
  data.codeVerifier = verifier;
  grant1.authData = data;

  grant1.isValid.should.equal(true);

  auto grant2 = createTestGrant(store);
  grant2.authData = data;

  grant2.isValid.should.equal(false);
}

} // version(unittest)
