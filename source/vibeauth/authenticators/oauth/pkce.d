module vibeauth.authenticators.oauth.pkce;

import std.conv;
import std.digest.sha;
import std.base64;
import std.uuid;

import vibe.crypto.cryptorand;

/// Validates a PKCE (RFC 7636) code verifier against a stored challenge.
/// Hashes the verifier with SHA-256, base64url-encodes it (no padding),
/// and compares it to the challenge from the authorization request.
/// Only the S256 method is supported; returns false for anything else.
bool verifyPkce(string codeVerifier, string codeChallenge, string method) {
  if (method != "S256") {
    return false;
  }

  auto hash = sha256Of(cast(const(ubyte)[]) codeVerifier);
  string encoded = Base64URL.encode(hash[]).idup;

  // Strip trailing '=' padding for BASE64URL_NO_PAD
  while (encoded.length > 0 && encoded[$ - 1] == '=') {
    encoded = encoded[0 .. $ - 1];
  }

  return encoded == codeChallenge;
}

string generateAuthorizationCode() {
  ubyte[16] secret;
  secureRNG.read(secret[]);
  return UUID(secret).to!string;
}

version(unittest) {
  import fluent.asserts;
}

@("verifyPkce validates correct S256 challenge")
unittest {
  auto verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  auto hash = sha256Of(cast(const(ubyte)[]) verifier);
  string challenge = Base64URL.encode(hash[]).idup;

  while (challenge.length > 0 && challenge[$ - 1] == '=') {
    challenge = challenge[0 .. $ - 1];
  }

  verifyPkce(verifier, challenge, "S256").should.equal(true);
}

@("verifyPkce rejects wrong verifier")
unittest {
  verifyPkce("wrong-verifier", "some-challenge", "S256").should.equal(false);
}

@("verifyPkce rejects unsupported method")
unittest {
  verifyPkce("verifier", "challenge", "plain").should.equal(false);
}

@("generateAuthorizationCode returns unique codes")
unittest {
  auto code1 = generateAuthorizationCode();
  auto code2 = generateAuthorizationCode();

  (code1.length > 0).should.equal(true);
  code1.should.not.equal(code2);
}
