module vibeauth.protocols.oauth2.auth;

import vibe.inet.url;
import vibe.http.router;
import vibe.http.server;
import vibe.data.json;
import vibe.core.log;

import vibeauth.protocols.oauth2.authdata;
import vibeauth.protocols.oauth2.clientprovider;
import vibeauth.protocols.oauth2.codestore;
import vibeauth.protocols.oauth2.serverprovider;
import vibeauth.protocols.oauth2.pkce;
import vibeauth.protocols.base;
import vibeauth.http.responses;
import vibeauth.http.accesscontrol;
import vibeauth.identity.usercollection;
import vibeauth.identity.user;

import std.datetime;
import std.stdio;
import std.string;
import std.conv;
import std.format;


/// OAuth2 configuration
struct OAuth2Configuration {
  /// Route for generating tokens
  string tokenPath = "/auth/token";

  /// Route for authorization
  string authorizePath = "/auth/authorize";

  /// Route for authentication
  string authenticatePath = "/auth/authenticate";

  /// Route for completing authorization (generates auth code)
  string authorizeCompletePath = "/auth/authorize/complete";

  /// Route for revoking tokens
  string revokePath = "/auth/revoke";

  /// Route for dynamic client registration (RFC 7591)
  string registrationPath = "/auth/register";

  /// Path of the login page — the authorize endpoint redirects here
  string loginPath = "/sign-in";

  /// Custom style to be embeded into the html
  string style;
}

/// Resolves the display name for a dynamically registered OAuth client.
/// Falls back through RFC 7591 fields and vendor metadata so the stored name
/// is never empty even when the client omits `client_name`.
package string resolveClientName(Json body_) {
  auto name = body_["client_name"].opt!string("").strip;
  if (name.length > 0) {
    return name;
  }

  auto metadataJson = body_["metadata"];
  if (metadataJson.type == Json.Type.object) {
    auto appName = metadataJson["app_name"].opt!string("").strip;
    if (appName.length > 0) {
      return appName;
    }
  }

  auto softwareId = body_["software_id"].opt!string("").strip;
  if (softwareId.length > 0) {
    return softwareId;
  }

  return "Unnamed OAuth client";
}

/// Result of validating requested scopes for a given user at authorize-complete time.
/// Error message is empty on success, or a human-readable explanation on failure.
struct ScopeValidation {
  bool ok;
  string error;

  static ScopeValidation accept() {
    return ScopeValidation(true, "");
  }

  static ScopeValidation reject(string reason) {
    return ScopeValidation(false, reason);
  }
}

alias ScopeValidator = ScopeValidation delegate(User user, string[] scopes);

/// OAuth2 autenticator
class OAuth2 : BaseAuth {
  protected {
    const OAuth2Configuration configuration;
    AuthorizationCodeStore codeStore;
    AuthorizationServerProvider authServerProvider;
    ClientProvider clientProvider;
    ScopeValidator scopeValidator;
  }

  ///
  this(UserCollection userCollection, const OAuth2Configuration configuration = OAuth2Configuration(),
        AuthorizationServerProvider authServerProvider = null, ClientProvider clientProvider = null,
        ScopeValidator scopeValidator = null) {
    super(userCollection);

    this.configuration = configuration;
    this.codeStore = new AuthorizationCodeStore();
    this.authServerProvider = authServerProvider;
    this.clientProvider = clientProvider;
    this.scopeValidator = scopeValidator;
  }


  /// Handle the OAuth requests. Handles token creation, authorization
  /// authentication and revocation
  void tokenHandlers(HTTPServerRequest req, HTTPServerResponse res) {
    try {
      setAccessControl(res);
      if(req.method == HTTPMethod.OPTIONS) {
        res.statusCode = 200;
        res.writeBody("");
        return;
      }

      if(req.path == configuration.tokenPath) {
        createToken(req, res);
      }

      if(req.path == configuration.authorizePath) {
        authorize(req, res);
      }

      if(req.path == configuration.authorizeCompletePath) {
        authorizeComplete(req, res);
      }

      if(req.path == configuration.authenticatePath) {
        authenticate(req, res);
      }

      if(req.path == configuration.revokePath) {
        revoke(req, res);
      }

      if(req.path == configuration.registrationPath) {
        register(req, res);
      }
    } catch (Exception e) {
      version(unittest) {} else debug stderr.writeln(e);

      if(!res.headerWritten) {
        res.writeJsonBody(["error": e.msg], 500);
      }
    }
  }

  override {
    void mandatoryAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.mandatoryAuth(req, res);
    }

    void permissiveAuth(HTTPServerRequest req, HTTPServerResponse res) {
      super.permissiveAuth(req, res);
    }

    /// Auth handler that will fail if a successfull auth was not performed.
    /// This handler is usefull for routes that want to hide information to the
    /// public.
    AuthResult mandatoryAuth(HTTPServerRequest req) {
      auto result = AuthResult.success;

      if(req.method == HTTPMethod.OPTIONS) {
        return AuthResult.success;
      }

      result = isValidBearer(req);

      if(req.path == configuration.style) {
        result = AuthResult.success;
      }

      return result;
    }

    /// Auth handler that fails only if the auth fields are present and are not valid.
    /// This handler is usefull when a route should return different data when the user is
    /// logged in
    AuthResult permissiveAuth(HTTPServerRequest req) {
      if("Authorization" !in req.headers) {
        return AuthResult.success;
      }

      return mandatoryAuth(req);
    }

    void respondUnauthorized(HTTPServerResponse res) {
      vibeauth.http.responses.respondUnauthorized(res);
    }

    void respondInvalidToken(HTTPServerResponse res) {
      vibeauth.http.responses.respondUnauthorized(res, "Invalid token.", 400);
    }
  }

  private {
    /// Validate the authorization token
    AuthResult isValidBearer(HTTPServerRequest req) {
      auto pauth = "Authorization" in req.headers;

      if(pauth && (*pauth).startsWith("Bearer ")) {
        auto token = (*pauth)[7 .. $];

        try {
          auto const user = collection.byToken(token);
          req.username = user.id;
          req.context["email"] = user.email;
          req.context["user"] = user.toJson;
        } catch(Exception e) {
          logDiagnostic("Bearer token validation failed for path %s: %s", req.path, e.msg);
          return AuthResult.invalidToken;
        }

        logDiagnostic("Bearer token valid for user %s on path %s", req.username, req.path);
        return AuthResult.success;
      }

      return AuthResult.unauthorized;
    }

    /// Handle the authorization step — redirect to auth domain login page
    void authorize(HTTPServerRequest req, HTTPServerResponse res) {
      if("redirect_uri" !in req.query) {
        showError(res, "Missing `redirect_uri` parameter");
        return;
      }

      if("client_id" !in req.query) {
        showError(res, "Missing `client_id` parameter");
        return;
      }

      if("state" !in req.query) {
        showError(res, "Missing `state` parameter");
        return;
      }

      if(clientProvider !is null && clientProvider.getClient(req.query["client_id"]).id == "") {
        showError(res, "Unknown client_id");
        return;
      }

      if(authServerProvider is null) {
        showError(res, "Authorization server not configured");
        return;
      }

      auto authDomain = authServerProvider.getAuthDomain(req);

      auto redirectUrl = format!"%s%s?oauth=true&client_id=%s&redirect_uri=%s&state=%s"(
        authDomain,
        configuration.loginPath,
        req.query["client_id"],
        req.query["redirect_uri"],
        req.query["state"]
      );

      if("code_challenge" in req.query) {
        redirectUrl ~= format!"&code_challenge=%s"(req.query["code_challenge"]);
      }

      if("code_challenge_method" in req.query) {
        redirectUrl ~= format!"&code_challenge_method=%s"(req.query["code_challenge_method"]);
      }

      if("scope" in req.query) {
        redirectUrl ~= format!"&scope=%s"(req.query["scope"]);
      }

      res.redirect(redirectUrl);
    }

    /// Complete the authorization — validate credentials and return an auth code
    void authorizeComplete(HTTPServerRequest req, HTTPServerResponse res) {
      if(req.method != HTTPMethod.POST) {
        return;
      }

      Json body_;

      try {
        body_ = req.json;
      } catch (Exception e) {
        res.writeJsonBody(["error": "Invalid JSON body"], 400);
        return;
      }

      auto email = body_["email"].opt!string("");
      auto password = body_["password"].opt!string("");
      auto clientId = body_["client_id"].opt!string("");
      auto redirectUri = body_["redirect_uri"].opt!string("");
      auto codeChallenge = body_["code_challenge"].opt!string("");
      auto codeChallengeMethod = body_["code_challenge_method"].opt!string("S256");
      auto state = body_["state"].opt!string("");

      if(clientProvider !is null && clientProvider.getClient(clientId).id == "") {
        res.writeJsonBody(["error": "Unknown client_id"], 400);
        return;
      }

      if(redirectUri.length == 0) {
        res.writeJsonBody(["error": "Missing redirect_uri"], 400);
        return;
      }

      auto pauth = "Authorization" in req.headers;
      bool hasBearer = pauth !is null && (*pauth).startsWith("Bearer ");

      if(email.length == 0 && !hasBearer) {
        res.writeJsonBody(["error": "Missing email or password"], 400);
        return;
      }

      User user;

      if(hasBearer) {
        auto token = (*pauth)[7 .. $];
        try {
          user = collection.byToken(token);
        } catch(Exception e) {
          res.writeJsonBody(["error": "Invalid token"], 401);
          return;
        }
      } else {
        if(password.length == 0) {
          res.writeJsonBody(["error": "Missing email or password"], 400);
          return;
        }
        if(!collection.contains(email) || !collection[email].isValidPassword(password)) {
          res.writeJsonBody(["error": "Invalid email or password"], 401);
          return;
        }
        user = collection[email];
      }

      auto code = generateAuthorizationCode();

      string[] scopes;
      auto scopeVal = body_["scope"];
      if(scopeVal.type == Json.Type.string) {
        scopes = scopeVal.get!string.split(" ");
      }

      if(scopeValidator !is null) {
        auto validation = scopeValidator(user, scopes);
        if(!validation.ok) {
          res.writeJsonBody(["error": validation.error], 403);
          return;
        }
      }

      AuthorizationCodeData codeData;
      codeData.code = code;
      codeData.userId = user.id;
      codeData.clientId = clientId;
      codeData.redirectUri = redirectUri;
      codeData.codeChallenge = codeChallenge;
      codeData.codeChallengeMethod = codeChallengeMethod;
      codeData.scopes = scopes;

      codeStore.store(codeData);

      auto response = Json.emptyObject;
      response["code"] = code;
      response["redirect_uri"] = redirectUri;
      response["state"] = state;

      res.writeJsonBody(response);
    }


    /// Show an HTML error
    void showError(HTTPServerResponse res, const string error) {
      res.statusCode = 400;
      res.writeJsonBody(["error": error]);
    }

    void authenticate(HTTPServerRequest req, HTTPServerResponse res) {
      string email;
      string password;

      try {
        email = req.form["email"];
        password = req.form["password"];
      } catch (Exception e) {
        debug showError(res, e.to!string);
        return;
      }

      if(!collection.contains(email) || !collection[email].isValidPassword(password)) {
        showError(res, "Invalid email or password.");
        return;
      }

      auto token = collection[email].createToken(Clock.currTime + 3601.seconds);
      auto redirectUri = req.form["redirect_uri"] ~ "#access_token=" ~ token.name ~ "&state=" ~ req.form["state"];

      //res.render!("redirect.dt", redirectUri);
    }

    /// Create token for the requested user
    void createToken(HTTPServerRequest req, HTTPServerResponse res) {
      auto grant = req.getAuthData(codeStore);

      grant.userCollection = collection;
      auto result = grant.get;
      res.statusCode = "error" !in result ? 200 : 401;
      res.writeJsonBody(result);
    }

    /// Revoke a previously created token using a POST request
    void revoke(HTTPServerRequest req, HTTPServerResponse res) {
      if(req.method != HTTPMethod.POST) {
        return;
      }

      if("token" !in req.form) {
        res.statusCode = 400;
        res.writeJsonBody(["error": "You must provide a `token` parameter."]);

        return;
      }

      auto const token = req.form["token"];
      collection.revoke(token);

      res.setCookie("ember_simple_auth-session", null);
      res.statusCode = 200;
      res.writeBody("");
    }

    /// Dynamic Client Registration (RFC 7591) — POST /auth/register
    void register(HTTPServerRequest req, HTTPServerResponse res) {
      if(req.method != HTTPMethod.POST) {
        return;
      }

      if(clientProvider is null) {
        res.writeJsonBody(["error": "client_registration_not_supported"], 400);
        return;
      }

      Json body_;

      try {
        body_ = req.json;
      } catch (Exception e) {
        res.writeJsonBody(["error": "Invalid JSON body"], 400);
        return;
      }

      auto redirectUrisJson = body_["redirect_uris"];

      if(redirectUrisJson.type != Json.Type.array || redirectUrisJson.length == 0) {
        res.writeJsonBody(["error": "redirect_uris is required and must be a non-empty array"], 400);
        return;
      }

      Client client;
      client.id = generateAuthorizationCode();
      client.name = resolveClientName(body_);

      string[] redirectUris;
      foreach(uri; redirectUrisJson) {
        redirectUris ~= uri.get!string;
      }
      client.redirectUris = redirectUris;

      auto metadataJson = body_["metadata"];
      if (metadataJson.type == Json.Type.object) {
        foreach (string key, value; metadataJson) {
          if (value.type == Json.Type.string) {
            client.metadata[key] = value.get!string;
          }
        }
      }

      auto registered = clientProvider.registerClient(client);

      auto response = Json.emptyObject;
      response["client_id"] = registered.id;
      response["client_name"] = registered.name;

      auto urisJson = Json.emptyArray;
      foreach(uri; registered.redirectUris) {
        urisJson ~= Json(uri);
      }
      response["redirect_uris"] = urisJson;

      auto grantTypes = body_["grant_types"];
      response["grant_types"] = grantTypes.type == Json.Type.array ? grantTypes : Json([Json("authorization_code")]);
      response["token_endpoint_auth_method"] = body_["token_endpoint_auth_method"].opt!string("none");
      response["response_types"] = Json([Json("code")]);

      res.statusCode = 201;
      res.writeJsonBody(response);
    }
  }
}

