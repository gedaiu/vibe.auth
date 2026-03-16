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
