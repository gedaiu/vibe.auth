module vibeauth.authenticators.oauth.AuthorizationCodeGrantAccess;

import vibeauth.authenticators.oauth.IGrantAccess;
import vibeauth.authenticators.oauth.AuthData;
import vibeauth.authenticators.oauth.AuthorizationCodeStore;
import vibeauth.authenticators.oauth.pkce;
import vibeauth.collections.usercollection;

import std.datetime;
import std.typecons;

import vibe.data.json;

version(unittest) {
  import vibeauth.collections.usermemory;
  import vibeauth.data.user;
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

    auto accessToken = collection.createToken(email, Clock.currTime + 3601.seconds, codeData.get.scopes, "Bearer");
    auto refreshToken = collection.createToken(email, Clock.currTime + 4.weeks, codeData.get.scopes ~ ["refresh"], "Refresh");

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

  assert(!grant.isValid);
}

@("isValid returns false when code does not exist in store")
unittest {
  auto store = new AuthorizationCodeStore();
  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "nonexistent-code";
  grant.authData = data;

  assert(!grant.isValid);
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

  assert(!grant.isValid);
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

  assert(!grant.isValid);
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

  assert(grant.isValid);
}

@("get returns error JSON when validation fails")
unittest {
  auto store = new AuthorizationCodeStore();
  auto grant = createTestGrant(store);

  AuthData data;
  data.code = "";
  grant.authData = data;

  auto response = grant.get;
  assert(response["error"].get!string == "Invalid authorization code or PKCE verification failed");
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

  assert(response["access_token"].type == Json.Type.string);
  assert(response["refresh_token"].type == Json.Type.string);
  assert(response["token_type"].get!string == "Bearer");
  assert(response["expires_in"].get!long > 0);
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

  assert(grant1.isValid);

  auto grant2 = createTestGrant(store);
  grant2.authData = data;

  assert(!grant2.isValid);
}

} // version(unittest)
