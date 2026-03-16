module vibeauth.authenticators.oauth.AuthorizationCodeStore;

import std.datetime;
import std.typecons;

struct AuthorizationCodeData {
  string code;
  string userId;
  string clientId;
  string redirectUri;
  string codeChallenge;
  string codeChallengeMethod;
  string[] scopes;
  SysTime createdAt;
}

class AuthorizationCodeStore {
  private {
    AuthorizationCodeData[string] codes;
    Duration ttl;
  }

  this(Duration ttl = 10.minutes) {
    this.ttl = ttl;
  }

  void store(AuthorizationCodeData data) {
    data.createdAt = Clock.currTime;
    codes[data.code] = data;
  }

  Nullable!AuthorizationCodeData consume(string code) {
    cleanup();

    if (code !in codes) {
      return Nullable!AuthorizationCodeData.init;
    }

    auto data = codes[code];
    codes.remove(code);

    if (Clock.currTime - data.createdAt > ttl) {
      return Nullable!AuthorizationCodeData.init;
    }

    return nullable(data);
  }

  private void cleanup() {
    auto now = Clock.currTime;
    string[] expired;

    foreach (key, data; codes) {
      if (now - data.createdAt > ttl) {
        expired ~= key;
      }
    }

    foreach (key; expired) {
      codes.remove(key);
    }
  }
}

version(unittest) {
  import fluent.asserts;
}

@("store and consume returns stored code data")
unittest {
  auto store = new AuthorizationCodeStore();

  AuthorizationCodeData data;
  data.code = "abc123";
  data.userId = "42";
  data.redirectUri = "https://example.com/callback";
  store.store(data);

  auto result = store.consume("abc123");

  result.isNull.should.equal(false);
  result.get.userId.should.equal("42");
  result.get.redirectUri.should.equal("https://example.com/callback");
}

@("consume returns null for nonexistent code")
unittest {
  auto store = new AuthorizationCodeStore();
  auto result = store.consume("doesnotexist");

  result.isNull.should.equal(true);
}

@("consume removes code after first use")
unittest {
  auto store = new AuthorizationCodeStore();

  AuthorizationCodeData data;
  data.code = "one-use";
  store.store(data);

  auto first = store.consume("one-use");
  auto second = store.consume("one-use");

  first.isNull.should.equal(false);
  second.isNull.should.equal(true);
}

@("consume returns null for expired codes")
unittest {
  auto store = new AuthorizationCodeStore(1.msecs);

  AuthorizationCodeData data;
  data.code = "expiring";
  store.store(data);

  import core.thread : Thread;
  Thread.sleep(5.msecs);

  auto result = store.consume("expiring");
  result.isNull.should.equal(true);
}

@("store sets createdAt timestamp")
unittest {
  auto store = new AuthorizationCodeStore();

  AuthorizationCodeData data;
  data.code = "timestamped";
  store.store(data);

  auto result = store.consume("timestamped");

  result.isNull.should.equal(false);
  (result.get.createdAt != SysTime.init).should.equal(true);
}
