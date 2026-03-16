module vibeauth.protocols.oauth2.authdata;

import vibeauth.protocols.oauth2.grants.password;
import vibeauth.protocols.oauth2.grants.refresh;
import vibeauth.protocols.oauth2.grants.authcode;
import vibeauth.protocols.oauth2.codestore;
import vibeauth.protocols.oauth2.grants.unknown;
import vibeauth.protocols.oauth2.grants.access;

import vibe.http.server;

import std.string;

/// Struct used for user authentication
struct AuthData {
  ///
  string username;
  ///
  string password;
  ///
  string refreshToken;
  /// The authorization scopes
  string[] scopes;
  /// Authorization code (for authorization_code grant)
  string code;
  /// PKCE code verifier (for authorization_code grant)
  string codeVerifier;
  /// Redirect URI (for authorization_code grant)
  string redirectUri;
}

/// Get the right access generator
IGrantAccess getAuthData(HTTPServerRequest req, AuthorizationCodeStore codeStore = null) {
  AuthData data;

  if ("refresh_token" in req.form) {
    data.refreshToken = req.form["refresh_token"];
  }

  if ("username" in req.form) {
    data.username = req.form["username"];
  }

  if ("password" in req.form) {
    data.password = req.form["password"];
  }

  if ("scope" in req.form) {
    data.scopes = req.form["scope"].split(" ");
  }

  if ("code" in req.form) {
    data.code = req.form["code"];
  }

  if ("code_verifier" in req.form) {
    data.codeVerifier = req.form["code_verifier"];
  }

  if ("redirect_uri" in req.form) {
    data.redirectUri = req.form["redirect_uri"];
  }

  if ("grant_type" in req.form) {
    if (req.form["grant_type"] == "password") {
      auto grant = new PasswordGrantAccess;
      grant.authData = data;

      return grant;
    }

    if (req.form["grant_type"] == "refresh_token") {
      auto grant = new RefreshTokenGrantAccess;
      grant.authData = data;

      return grant;
    }

    if (req.form["grant_type"] == "authorization_code" && codeStore !is null) {
      auto grant = new AuthorizationCodeGrantAccess(codeStore);
      grant.authData = data;

      return grant;
    }
  }

  return new UnknownGrantAccess;
}
