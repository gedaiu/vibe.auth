module vibeauth.authenticators.oauth.AuthData;

import vibeauth.authenticators.oauth.PasswordGrantAccess;
import vibeauth.authenticators.oauth.RefreshTokenGrantAccess;
import vibeauth.authenticators.oauth.AuthorizationCodeGrantAccess;
import vibeauth.authenticators.oauth.AuthorizationCodeStore;
import vibeauth.authenticators.oauth.UnknownGrantAccess;
import vibeauth.authenticators.oauth.IGrantAccess;

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
